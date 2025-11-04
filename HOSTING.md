# Hosting Options for Omni Embed Tester

This Node.js/Express app can be hosted on several platforms. Here are the best options:

## 🚀 Recommended Hosting Platforms

### 1. **Render** (Recommended - Free tier available)
- **Why**: Easy deployment, automatic HTTPS, free tier
- **Setup**: 
  - Connect your GitHub repo to Render
  - Select "Web Service"
  - Build command: `npm install`
  - Start command: `npm start`
  - Set environment variable: `PORT=3000` (or let Render auto-assign)
- **Cost**: Free tier available, paid plans start at $7/month
- **URL**: https://render.com

### 2. **Railway** (Great for quick deployment)
- **Why**: Very simple, good free tier
- **Setup**: 
  - Connect GitHub repo
  - Auto-detects Node.js
  - Update `server.js` to use `process.env.PORT || 3000`
- **Cost**: Free tier with $5 credit/month, pay-as-you-go
- **URL**: https://railway.app

### 3. **Heroku** (Classic choice)
- **Why**: Well-established, reliable
- **Setup**: 
  - Install Heroku CLI
  - `heroku create your-app-name`
  - `git push heroku main`
  - Uses `Procfile` for start command
- **Cost**: Free tier discontinued, paid plans start at $5/month
- **URL**: https://heroku.com

### 4. **Fly.io** (Good for global distribution)
- **Why**: Fast, global edge deployment
- **Setup**: 
  - Install Fly CLI
  - `fly launch` (auto-detects Node.js)
  - Configure `fly.toml`
- **Cost**: Free tier available, pay-as-you-go
- **URL**: https://fly.io

### 5. **Vercel** (Best for static + API routes)
- **Why**: Excellent for frontend + API routes
- **Setup**: 
  - Connect GitHub repo
  - Configure as Node.js app
  - May need to separate frontend/backend
- **Cost**: Free tier available
- **URL**: https://vercel.com

### 6. **Netlify** (Good for static + functions)
- **Why**: Great for static sites with serverless functions
- **Setup**: 
  - Connect GitHub repo
  - Use Netlify Functions for API endpoints
  - May require code restructuring
- **Cost**: Free tier available
- **URL**: https://netlify.com

### 7. **DigitalOcean App Platform**
- **Why**: Simple, predictable pricing
- **Setup**: 
  - Connect GitHub repo
  - Auto-detects Node.js
  - Configure build/start commands
- **Cost**: Starts at $5/month
- **URL**: https://www.digitalocean.com/products/app-platform

## 📝 Pre-Deployment Checklist

Before deploying, you'll need to:

1. **Update server.js** to use environment port:
   ```javascript
   const PORT = process.env.PORT || 3000;
   ```

2. **Remove sudo requirement** (not needed in cloud):
   ```json
   // package.json - remove sudo from scripts
   "start": "node server.js",
   "dev": "nodemon server.js"
   ```

3. **Add Procfile** (for Heroku compatibility):
   ```
   web: node server.js
   ```

4. **Environment Variables** (if needed):
   - Set via hosting platform's dashboard
   - Example: `PORT=3000`

5. **CORS Configuration**: 
   - Update CORS settings in `server.js` if needed
   - Add your production domain to allowed origins

## 🔧 Quick Start: Render Deployment

1. **Push to GitHub** (if not already):
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin YOUR_GITHUB_REPO_URL
   git push -u origin main
   ```

2. **Deploy on Render**:
   - Go to https://render.com
   - Sign up/login
   - Click "New +" → "Web Service"
   - Connect your GitHub repo
   - Settings:
     - **Name**: omni-embed-tester
     - **Environment**: Node
     - **Build Command**: `npm install`
     - **Start Command**: `npm start`
   - Click "Create Web Service"

3. **Done!** Your app will be live at `https://your-app.onrender.com`

## ⚠️ Important Notes

- **Port 80 requirement**: The localhost port 80 requirement is only for local development. In production, you can use any port (the hosting platform will handle routing).
- **HTTPS**: All hosting platforms provide HTTPS automatically, which is better for production.
- **CORS**: You may need to update CORS settings in `server.js` to allow your production domain.
- **Proxy endpoints**: The `/proxy/*` endpoint should work fine in production as long as the target Omni servers allow your domain.

## 🎯 Which Should You Choose?

- **Quick & Free**: Render or Railway
- **Simple & Reliable**: Heroku or DigitalOcean
- **Global Performance**: Fly.io
- **Frontend-focused**: Vercel or Netlify

For most use cases, **Render** or **Railway** are the best choices - they're free, easy to set up, and work great for Node.js apps.

