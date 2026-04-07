# Expense Tracker

A beautiful, minimalist expense tracking app built with Express.js and PostgreSQL (Neon).

## Features

- Add, view, and delete expenses
- Track spending by category
- Daily, weekly, and monthly analytics
- Visual charts and statistics
- Export expenses to Excel
- Store data in PostgreSQL database

## Local Setup

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Create `.env` file**
   ```
   DATABASE_URL=postgresql://user:password@host/dbname?sslmode=require
   PORT=3000
   ```

3. **Run the server**
   ```bash
   npm start
   ```

4. **Open in browser**
   ```
   http://localhost:3000
   ```

## Deployment on Railway

### Option 1: Using Railway CLI (Recommended)

1. **Install Railway CLI**
   ```bash
   npm install -g @railway/cli
   ```

2. **Login to Railway**
   ```bash
   railway login
   ```

3. **Init and deploy**
   ```bash
   railway init
   railway up
   ```

4. **Add environment variables in Railway dashboard**
   - Go to your Railway project
   - Add `DATABASE_URL` variable with your Neon PostgreSQL connection string
   - Railway will automatically detect PORT

### Option 2: Using Railway Dashboard

1. Go to [railway.app](https://railway.app)
2. Create new project → Deploy from GitHub
3. Connect your GitHub repository
4. Configure environment variables
5. Railway auto-deploys on push

## Database Setup

1. Create a free PostgreSQL database on [Neon](https://neon.tech)
2. Copy the connection string
3. Add to Railway environment variables as `DATABASE_URL`

## Free Tier Info

Railway offers:
- Free tier with $5/month credit
- Enough for this app and small PostgreSQL database
- Pay-as-you-go after credits run out

## Tech Stack

- **Frontend**: HTML, CSS, JavaScript
- **Backend**: Node.js, Express.js
- **Database**: PostgreSQL (Neon)
- **Charts**: Chart.js
- **Export**: XLSX library
