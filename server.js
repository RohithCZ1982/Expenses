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
app.use(express.json());
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
