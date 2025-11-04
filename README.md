# Omni Embed Tester

A testing application for Omni Analytics embedding with hot reloading support.

## Features

- 🔥 **Hot Reloading**: Automatically refreshes when you make changes to HTML, CSS, or JavaScript files
- 🚀 **Live Preview**: See changes instantly in the browser
- 🔧 **Development Mode**: Optimized for rapid development and testing
- 📱 **Responsive UI**: Modern, mobile-friendly interface
- 🔐 **Omni Integration**: Full support for Omni Analytics embedding

## Quick Start

### Development Mode (with hot reloading)
```bash
npm run dev
```
This will start the server with nodemon on port 80, which automatically restarts when you make changes to any file.

### Production Mode
```bash
npm start
```

**Note**: Both commands require `sudo` because the app runs on port 80 to avoid CSP (Content Security Policy) issues with Omni's embedding.

## Hot Reloading

The app includes two levels of hot reloading:

1. **Server-side**: Nodemon automatically restarts the server when you change `server.js`
2. **Client-side**: The browser automatically refreshes when you change `index.html`, `script.js`, or `styles.css`

### How it works

- The server watches for file changes using nodemon
- The client checks for file changes every 2 seconds via `/api/check-updates`
- When changes are detected, the browser automatically reloads
- Only works on localhost for security

## Development Tips

- Make changes to any file and see them instantly
- The server will restart automatically for backend changes
- The browser will refresh automatically for frontend changes
- Check the browser console for reload notifications

## Available Scripts

- `npm run dev` - Start development server with hot reloading
- `npm start` - Start production server
- `npm install` - Install dependencies

## File Structure

```
├── index.html          # Main HTML file
├── script.js           # JavaScript logic
├── styles.css          # CSS styles
├── server.js           # Express server
├── package.json        # Dependencies and scripts
├── nodemon.json        # Nodemon configuration
└── README.md           # This file
```

## Port Requirements

The app runs on port 80 (not 8080) to avoid Content Security Policy (CSP) issues:

- **Why port 80?** Omni's embedding only allows iframe embedding from `http://localhost` (without port number)
- **Why sudo?** Port 80 requires administrator privileges on most systems
- **Alternative**: You can run on a different port by setting `PORT=8080 npm start`, but the iframe will be blocked by CSP

## Troubleshooting

If hot reloading isn't working:

1. Make sure you're using `npm run dev` (not `npm start`)
2. Check that you're accessing the app via `http://localhost` (no port number)
3. Look for error messages in the browser console
4. Restart the development server if needed

If you see "Content Security Policy is blocking the iframe":

1. Make sure you're running on port 80 (`http://localhost`)
2. Use `sudo npm run dev` or `sudo npm start`
3. Check that no other process is using port 80

## API Endpoints

- `GET /` - Main application
- `POST /api/generate-url` - Generate Omni embed URLs
- `GET /proxy/*` - Proxy for iframe content
- `GET /api/check-updates` - Check for file changes (hot reload)