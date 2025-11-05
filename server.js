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

// Helper function to rewrite URLs in content to go through proxy
function rewriteUrls(content, omniHostname, basePath) {
    // Extract the Omni hostname from the URL
    // omniHostname will be like "peter.embed-omniapp.co"
    
    // Rewrite absolute URLs to Omni domain (most common case)
    const omniDomainRegex = new RegExp(`https?://${omniHostname.replace(/\./g, '\\.')}(/[^"\'\\s>]*)?`, 'gi');
    content = content.replace(omniDomainRegex, (match) => {
        try {
            const url = match;
            const urlObj = new URL(url);
            return `/proxy/${omniHostname}${urlObj.pathname || '/'}${urlObj.search}${urlObj.hash}`;
        } catch (e) {
            // If URL parsing fails, just rewrite the domain part
            return match.replace(new RegExp(`https?://${omniHostname.replace(/\./g, '\\.')}`, 'i'), `/proxy/${omniHostname}`);
        }
    });
    
    // Rewrite relative URLs in HTML attributes (href, src, action, etc.)
    content = content.replace(/(href|src|action|data-src|data-href|data-url|url|background|background-image)\s*=\s*["'](\/[^"']*)["']/gi, (match, attr, url) => {
        // If it's already a proxy path, leave it
        if (url.startsWith('/proxy/')) return match;
        // Skip if it's a protocol-relative URL (//)
        if (url.startsWith('//')) return match;
        // Otherwise, prepend the base path
        return `${attr}="${basePath}${url}"`;
    });
    
    // Rewrite link tags with rel="stylesheet" - these are critical for CSS
    content = content.replace(/<link([^>]*)\s+href\s*=\s*["']([^"']+)["']([^>]*)>/gi, (match, before, href, after) => {
        // Check if it's a stylesheet link
        if (match.includes('stylesheet') || match.includes('text/css')) {
            if (href.startsWith('http://') || href.startsWith('https://')) {
                if (href.includes(omniHostname)) {
                    try {
                        const urlObj = new URL(href);
                        return `<link${before} href="/proxy/${omniHostname}${urlObj.pathname}${urlObj.search}"${after}>`;
                    } catch (e) {
                        return match;
                    }
                }
            } else if (href.startsWith('/') && !href.startsWith('/proxy/')) {
                return `<link${before} href="${basePath}${href}"${after}>`;
            }
        }
        return match;
    });
    
    // Rewrite URLs in CSS (url() functions)
    content = content.replace(/url\s*\(\s*["']?([^"')]+)["']?\s*\)/gi, (match, url) => {
        url = url.trim();
        if (url.startsWith('http://') || url.startsWith('https://')) {
            if (url.includes(omniHostname)) {
                try {
                    const urlObj = new URL(url);
                    return `url("/proxy/${omniHostname}${urlObj.pathname}${urlObj.search}")`;
                } catch (e) {
                    return match;
                }
            }
        } else if (url.startsWith('/') && !url.startsWith('/proxy/')) {
            return `url("${basePath}${url}")`;
        }
        return match;
    });
    
    // Rewrite CSS @import statements
    content = content.replace(/@import\s+["']([^"']+)["']/gi, (match, url) => {
        if (url.startsWith('http://') || url.startsWith('https://')) {
            if (url.includes(omniHostname)) {
                try {
                    const urlObj = new URL(url);
                    return `@import "/proxy/${omniHostname}${urlObj.pathname}${urlObj.search}"`;
                } catch (e) {
                    return match;
                }
            }
        } else if (url.startsWith('/') && !url.startsWith('/proxy/')) {
            return `@import "${basePath}${url}"`;
        }
        return match;
    });
    
    // Rewrite fetch() calls in JavaScript
    content = content.replace(/fetch\s*\(\s*["']([^"']+)["']/gi, (match, url) => {
        if (url.startsWith('http://') || url.startsWith('https://')) {
            if (url.includes(omniHostname)) {
                try {
                    const urlObj = new URL(url);
                    return `fetch("/proxy/${omniHostname}${urlObj.pathname}${urlObj.search}${urlObj.hash}")`;
                } catch (e) {
                    return match;
                }
            }
        } else if (url.startsWith('/') && !url.startsWith('/proxy/')) {
            return `fetch("${basePath}${url}")`;
        }
        return match;
    });
    
    // Rewrite XMLHttpRequest open URLs
    content = content.replace(/\.open\s*\(\s*["'][^"']+["']\s*,\s*["']([^"']+)["']/gi, (match, url) => {
        if (url.includes(omniHostname)) {
            try {
                const fullUrl = url.startsWith('http') ? url : `https://${omniHostname}${url}`;
                const urlObj = new URL(fullUrl);
                return match.replace(url, `/proxy/${omniHostname}${urlObj.pathname}${urlObj.search}${urlObj.hash}`);
            } catch (e) {
                return match;
            }
        } else if (url.startsWith('/') && !url.startsWith('/proxy/')) {
            return match.replace(url, `${basePath}${url}`);
        }
        return match;
    });
    
    // Rewrite base tag href
    content = content.replace(/<base\s+[^>]*href\s*=\s*["']([^"']+)["']/gi, (match, url) => {
        if (url.includes(omniHostname) || url.startsWith('/')) {
            if (url.startsWith('http://') || url.startsWith('https://')) {
                try {
                    const urlObj = new URL(url);
                    return match.replace(url, `/proxy/${omniHostname}${urlObj.pathname}`);
                } catch (e) {
                    return match;
                }
            } else if (url.startsWith('/') && !url.startsWith('/proxy/')) {
                return match.replace(url, `${basePath}${url}`);
            }
        }
        return match;
    });
    
    return content;
}

// Proxy endpoint to serve Omni content with correct headers
app.get('/proxy/*', async (req, res) => {
    try {
        let omniUrl = req.url.replace('/proxy/', 'https://');
        console.log('Proxying request to:', omniUrl);
        
        // Extract the Omni hostname for URL rewriting
        const urlMatch = omniUrl.match(/https?:\/\/([^\/]+)/);
        const omniHostname = urlMatch ? urlMatch[1] : '';
        const basePath = `/proxy/${omniHostname}`;
        
        // Forward cookies from the request
        const cookieHeader = req.headers.cookie || '';
        
        // Forward other important headers
        const headers = {
            'User-Agent': req.get('user-agent') || 'Mozilla/5.0',
            'Accept': req.get('accept') || '*/*',
            'Accept-Language': req.get('accept-language') || 'en-US,en;q=0.9',
            'Referer': omniUrl, // Set referer to the Omni domain
            'Origin': `https://${omniHostname}`, // Set origin to Omni domain
        };
        
        if (cookieHeader) {
            headers['Cookie'] = cookieHeader;
        }
        
        // Fetch with redirect following
        const response = await fetch(omniUrl, {
            method: req.method || 'GET',
            headers: headers,
            redirect: 'follow',
        });
        
        // Get content type
        const contentType = response.headers.get('content-type') || 'text/html';
        const isText = contentType.includes('text/') || 
                      contentType.includes('application/javascript') ||
                      contentType.includes('application/json') ||
                      contentType.includes('application/xml') ||
                      contentType.includes('text/css');
        
        let content;
        if (isText) {
            content = await response.text();
        } else {
            // For binary content, get as buffer
            const buffer = await response.arrayBuffer();
            content = Buffer.from(buffer);
        }
        
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
        
        // Rewrite URLs in text content (HTML, JS, CSS)
        let modifiedContent = content;
        if (isText && typeof content === 'string') {
            // Remove CSP meta tags
            modifiedContent = content
                .replace(/<meta[^>]*http-equiv=["']Content-Security-Policy["'][^>]*>/gi, '')
                .replace(/content-security-policy[^>]*>/gi, '');
            
            // For CSS files, rewrite URLs within the CSS
            if (contentType.includes('text/css')) {
                // Rewrite URLs in CSS (imports, url() functions, etc.)
                modifiedContent = rewriteUrls(modifiedContent, omniHostname, basePath);
            } else {
                // For HTML/JS, rewrite all URLs
                modifiedContent = rewriteUrls(modifiedContent, omniHostname, basePath);
            }
        }
        
        // Set headers to allow iframe embedding from current origin
        // Also set permissive CSP for the iframe content itself
        res.set({
            'Content-Type': contentType,
            'X-Frame-Options': 'ALLOWALL',
            'Content-Security-Policy': `frame-ancestors 'self' ${currentOrigin} http://localhost:* http://127.0.0.1:* https://*; default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: ${currentOrigin} /proxy/ https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: ${currentOrigin} /proxy/ https:; style-src 'self' 'unsafe-inline' 'unsafe-hashes' data: blob: ${currentOrigin} /proxy/ https:; img-src 'self' data: blob: ${currentOrigin} /proxy/ https:; font-src 'self' data: blob: ${currentOrigin} /proxy/ https:; connect-src 'self' ${currentOrigin} /proxy/ https: http: wss: ws:;`,
            'X-Content-Type-Options': 'nosniff',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        });
        
        if (isText) {
            res.status(response.status).send(modifiedContent);
        } else {
            res.status(response.status).send(content);
        }
    } catch (error) {
        console.error('Proxy error:', error);
        console.error('Error details:', error.message, error.stack);
        res.status(500).send(`Proxy error: ${error.message}`);
    }
});

// Handle all HTTP methods for proxy (POST, PUT, DELETE, etc.)
['post', 'put', 'delete', 'patch'].forEach(method => {
    app[method]('/proxy/*', async (req, res) => {
        try {
            let omniUrl = req.url.replace('/proxy/', 'https://');
            console.log(`Proxying ${method.toUpperCase()} request to:`, omniUrl);
            
            const urlMatch = omniUrl.match(/https?:\/\/([^\/]+)/);
            const omniHostname = urlMatch ? urlMatch[1] : '';
            
            const headers = {
                'Content-Type': req.get('content-type') || 'application/json',
                'Cookie': req.headers.cookie || '',
                'User-Agent': req.get('user-agent') || 'Mozilla/5.0',
                'Origin': `https://${omniHostname}`,
                'Referer': omniUrl,
            };
            
            // Forward body
            let body = req.body;
            if (typeof body === 'object') {
                body = JSON.stringify(body);
            } else {
                body = req.body;
            }
            
            const response = await fetch(omniUrl, {
                method: method.toUpperCase(),
                headers: headers,
                body: body,
            });
            
            const contentType = response.headers.get('content-type') || 'application/json';
            const content = await response.text();
            
            // Forward cookies
            const setCookieHeaders = response.headers.raw()['set-cookie'];
            if (setCookieHeaders) {
                res.setHeader('Set-Cookie', setCookieHeaders);
            }
            
            res.set({
                'Content-Type': contentType,
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            });
            
            res.status(response.status).send(content);
        } catch (error) {
            console.error(`Proxy ${method} error:`, error);
            res.status(500).send(`Proxy error: ${error.message}`);
        }
    });
});

// Handle OPTIONS for CORS preflight
app.options('/proxy/*', (req, res) => {
    res.set({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    });
    res.status(200).send();
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