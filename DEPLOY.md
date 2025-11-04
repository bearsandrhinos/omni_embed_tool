# Deployment Guide for omni_embed_tool

Quick deployment guide for your repository: `git@github.com:bearsandrhinos/omni_embed_tool.git`

## 🚀 Quick Deploy Steps

### Option 1: Render (Recommended - Free & Easy)

1. **Initialize Git Repository** (if not already done):
   ```bash
   cd "/Users/peterwhitehead/Documents/embed app"
   git init
   git add .
   git commit -m "Initial commit - ready for deployment"
   git branch -M main
   git remote add origin git@github.com:bearsandrhinos/omni_embed_tool.git
   git push -u origin main
   ```

2. **Deploy on Render**:
   - Go to https://render.com and sign up/login
   - Click "New +" → "Web Service"
   - Click "Connect GitHub" and authorize Render
   - Select repository: `bearsandrhinos/omni_embed_tool`
   - Configure:
     - **Name**: `omni-embed-tool` (or any name you prefer)
     - **Environment**: `Node`
     - **Region**: Choose closest to you
     - **Branch**: `main`
     - **Root Directory**: `.` (leave empty)
     - **Build Command**: `npm install`
     - **Start Command**: `npm start`
   - Click "Create Web Service"
   - Wait 2-3 minutes for deployment
   - Your app will be live at: `https://omni-embed-tool.onrender.com` (or your chosen name)

3. **Done!** Your app is now live.

### Option 2: Railway (Even Simpler)

1. **Push to GitHub** (same as above)

2. **Deploy on Railway**:
   - Go to https://railway.app and sign up/login
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose `bearsandrhinos/omni_embed_tool`
   - Railway auto-detects Node.js and deploys
   - Your app will be live in ~2 minutes

### Option 3: Heroku (Classic)

1. **Push to GitHub** (same as above)

2. **Install Heroku CLI**:
   ```bash
   # macOS
   brew tap heroku/brew && brew install heroku
   
   # Or download from https://devcenter.heroku.com/articles/heroku-cli
   ```

3. **Deploy**:
   ```bash
   heroku login
   heroku create omni-embed-tool
   git push heroku main
   ```

4. **Done!** Your app will be at: `https://omni-embed-tool.herokuapp.com`

## 📝 Pre-Deployment Checklist

✅ **Already done:**
- Removed `sudo` from npm scripts
- Added `Procfile` for Heroku
- Updated server.js to use `process.env.PORT`
- Created `.gitignore`

## 🔧 Environment Variables

Most platforms don't require environment variables for this app, but if you need to set any:

- **Render**: Settings → Environment → Add Environment Variable
- **Railway**: Variables tab → Add Variable
- **Heroku**: `heroku config:set KEY=value`

## 🎯 Recommended: Render

For your use case, **Render** is the best choice because:
- ✅ Free tier available
- ✅ Automatic HTTPS
- ✅ Easy GitHub integration
- ✅ No credit card required (for free tier)
- ✅ Auto-deploys on git push

## 🔗 Your Repository

- **GitHub**: `git@github.com:bearsandrhinos/omni_embed_tool.git`
- **Clone URL**: `https://github.com/bearsandrhinos/omni_embed_tool.git`

## 🐛 Troubleshooting

**If deployment fails:**
1. Check build logs in the hosting platform dashboard
2. Ensure `package.json` has correct `start` script
3. Verify all dependencies are in `dependencies` (not `devDependencies`)
4. Check that `node` version is compatible (most platforms use Node 18+)

**If app doesn't work after deployment:**
1. Check CORS settings in `server.js` - may need to allow your production domain
2. Verify the app URL is accessible
3. Check browser console for errors
4. Review server logs in hosting dashboard

## 📞 Next Steps

1. Choose a hosting platform (Render recommended)
2. Push your code to GitHub
3. Connect repo to hosting platform
4. Deploy!
5. Share your live URL 🎉

