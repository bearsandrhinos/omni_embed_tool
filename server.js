const express = require('express');
const cors = require('cors');
const path = require('path');
const fetch = require('node-fetch');

const app = express();
// Use PORT from environment (cloud hosting) or default to 3000
// Port 80 is only needed for localhost to avoid CSP issues
const PORT = process.env.PORT || (process.env.NODE_ENV === 'production' ? 3000 : 80);

// Enable CORS for all routes
app.use(cors());

// Parse JSON bodies
app.use(express.json());

// Serve static files from the current directory
app.use(express.static(__dirname));

// Proxy endpoint for Omni API
app.post('/api/generate-url', async (req, res) => {
    try {
        const { hostname, ...params } = req.body;
        
        if (!hostname) {
            return res.status(400).json({ error: 'Hostname is required' });
        }

        const apiUrl = `https://${hostname}/embed/sso/generate-url`;
        
        console.log('Proxying request to:', apiUrl);
        console.log('Request body:', params);

        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(params)
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Omni API error:', response.status, errorText);
            return res.status(response.status).json({ 
                error: `Omni API error: ${response.status} ${response.statusText}`,
                details: errorText
            });
        }

        const result = await response.json();
        console.log('Omni API response:', result);
        
        res.json(result);

    } catch (error) {
        console.error('Proxy error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});

// Proxy endpoint to serve Omni content with correct headers
app.get('/proxy/*', async (req, res) => {
    try {
        let omniUrl = req.url.replace('/proxy/', 'https://');
        console.log('Proxying iframe request to:', omniUrl);
        
        // Forward cookies from the request
        const cookieHeader = req.headers.cookie || '';
        
        // Forward other important headers
        const headers = {
            'User-Agent': req.get('user-agent') || 'Mozilla/5.0',
            'Accept': req.get('accept') || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': req.get('accept-language') || 'en-US,en;q=0.9',
            'Referer': omniUrl, // Set referer to the Omni domain
        };
        
        if (cookieHeader) {
            headers['Cookie'] = cookieHeader;
        }
        
        // Fetch with redirect following
        const response = await fetch(omniUrl, {
            method: 'GET',
            headers: headers,
            redirect: 'follow',
            // Important: Don't follow redirects automatically, handle them manually
        });
        
        // Get content type
        const contentType = response.headers.get('content-type') || 'text/html';
        const content = await response.text();
        
        // Get the current origin to allow iframe embedding
        const origin = req.get('origin') || req.get('referer') || '';
        const host = req.get('host') || '';
        const protocol = req.protocol || 'https';
        const currentOrigin = origin || `${protocol}://${host}`;
        
        // Forward set-cookie headers from Omni to the client
        const setCookieHeaders = response.headers.raw()['set-cookie'];
        if (setCookieHeaders) {
            res.setHeader('Set-Cookie', setCookieHeaders);
        }
        
        // Set headers to allow iframe embedding from current origin
        res.set({
            'Content-Type': contentType,
            'X-Frame-Options': 'ALLOWALL',
            'Content-Security-Policy': `frame-ancestors 'self' ${currentOrigin} http://localhost:* http://127.0.0.1:* https://*`,
            // Remove CSP headers that might block
            'X-Content-Type-Options': 'nosniff',
        });
        
        res.status(response.status).send(content);
    } catch (error) {
        console.error('Proxy error:', error);
        console.error('Error details:', error.message, error.stack);
        res.status(500).send(`Proxy error: ${error.message}`);
    }
});

// Hot reload endpoint - check for file changes
app.get('/api/check-updates', (req, res) => {
    const fs = require('fs');
    const files = ['index.html', 'script.js', 'styles.css', 'server.js'];
    let maxModified = 0;
    
    files.forEach(file => {
        try {
            const stats = fs.statSync(path.join(__dirname, file));
            maxModified = Math.max(maxModified, stats.mtime.getTime());
        } catch (error) {
            // File doesn't exist, ignore
        }
    });
    
    res.json({ lastModified: maxModified });
});

// Catch-all for serving index.html for any other routes (SPA-like behavior)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
    console.log(`📁 Serving files from: ${__dirname}`);
    console.log(`🔗 Open http://localhost:${PORT} in your browser`);
});