require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// Database connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.static(__dirname));

// Initialize database table
async function initDB() {
  try {
    const query = `
      CREATE TABLE IF NOT EXISTS expenses (
        id BIGINT PRIMARY KEY,
        date DATE NOT NULL,
        amount DECIMAL NOT NULL,
        category VARCHAR(255) NOT NULL,
        note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_expenses_date ON expenses(date);
      CREATE INDEX IF NOT EXISTS idx_expenses_category ON expenses(category);
    `;
    await pool.query(query);
    
    // Clean up old data with wrong date format (timestamps instead of dates)
    await pool.query('DELETE FROM expenses WHERE date > CURRENT_DATE');
    
    console.log('Database initialized');
  } catch (err) {
    console.error('DB init error:', err);
  }
}

// Get all expenses
app.get('/api/expenses', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, TO_CHAR(date, \'YYYY-MM-DD\') as date, amount, category, note, created_at FROM expenses ORDER BY date DESC, created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add expense
app.post('/api/expenses', async (req, res) => {
  const { id, date, amount, category, note } = req.body;
  try {
    const query = 'INSERT INTO expenses (id, date, amount, category, note) VALUES ($1, $2::DATE, $3, $4, $5) RETURNING id, TO_CHAR(date, \'YYYY-MM-DD\') as date, amount, category, note';
    const result = await pool.query(query, [id, date, amount, category, note || null]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Scan a bill image with Gemini and extract expense details
const EXPENSE_CATEGORIES = [
  'Food & Dining', 'Groceries', 'Transport', 'Utilities', 'Health',
  'Shopping', 'Entertainment', 'Travel', 'Education', 'Rent', 'EMI',
  'Subscriptions', 'Gym & Fitness', 'Gifts', 'Personal Care', 'Other',
];

app.post('/api/scan-bill', async (req, res) => {
  const { image, mimeType } = req.body;
  if (!image) {
    return res.status(400).json({ error: 'No image provided' });
  }
  const mt = mimeType || 'image/jpeg';
  if (!/^image\//.test(mt) && mt !== 'application/pdf') {
    return res.status(400).json({ error: 'Only images and PDF bills are supported' });
  }
  if (!process.env.GEMINI_API_KEY) {
    return res.status(500).json({ error: 'GEMINI_API_KEY is not configured on the server' });
  }

  const prompt = `You are an expense-tracking assistant. Analyze this bill/receipt (image or PDF) and extract:
- "amount": the final total amount paid, as a number (no currency symbol). Use the grand total after taxes/discounts.
- "date": the bill date in YYYY-MM-DD format. If no date is visible, use null.
- "category": the best matching category from exactly this list: ${EXPENSE_CATEGORIES.join(', ')}.
- "owner": the name of the merchant/shop/business that issued the bill (the bill owner). If a person's name is on the bill instead, use that. Use null if not found.

Respond with ONLY a JSON object: {"amount": number|null, "date": "YYYY-MM-DD"|null, "category": string, "owner": string|null}
If the image is not a bill or receipt, respond with {"error": "not a bill"}.`;

  try {
    const geminiRes = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{
            parts: [
              { text: prompt },
              { inline_data: { mime_type: mt, data: image } },
            ],
          }],
          generationConfig: {
            temperature: 0,
            response_mime_type: 'application/json',
          },
        }),
      }
    );

    if (!geminiRes.ok) {
      const errBody = await geminiRes.text();
      console.error('Gemini API error:', geminiRes.status, errBody);
      return res.status(502).json({ error: 'AI service error (' + geminiRes.status + ')' });
    }

    const data = await geminiRes.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text) {
      return res.status(502).json({ error: 'AI returned an empty response' });
    }

    let parsed;
    try {
      parsed = JSON.parse(text.replace(/^```json\s*|```\s*$/g, ''));
    } catch (e) {
      console.error('Failed to parse Gemini response:', text);
      return res.status(502).json({ error: 'Could not parse AI response' });
    }

    if (parsed.error) {
      return res.status(422).json({ error: 'This image does not look like a bill or receipt' });
    }

    res.json({
      amount: typeof parsed.amount === 'number' ? parsed.amount : parseFloat(parsed.amount) || null,
      date: /^\d{4}-\d{2}-\d{2}$/.test(parsed.date || '') ? parsed.date : null,
      category: EXPENSE_CATEGORIES.includes(parsed.category) ? parsed.category : 'Other',
      owner: parsed.owner || null,
    });
  } catch (err) {
    console.error('Scan bill error:', err);
    res.status(500).json({ error: 'Failed to scan bill' });
  }
});

// Delete expense
app.delete('/api/expenses/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM expenses WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, async () => {
  console.log(`Server running on http://localhost:${PORT}`);
  try {
    await initDB();
  } catch (err) {
    console.error('DB initialization failed:', err.message);
    console.log('Server started anyway - frontend is available');
  }
});
