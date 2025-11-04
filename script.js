class OmniEmbedTester {
    constructor() {
        console.log('Initializing OmniEmbedTester...');
        this.initializeElements();
        console.log('Elements initialized');
        this.bindEvents();
        console.log('Events bound');
        this.loadPresets();
        console.log('Presets loaded');
        console.log('OmniEmbedTester initialized successfully');
        
        // Mark app as initialized
        window.omniApp = this;
    }

    initializeElements() {
        console.log('Initializing form elements...');
        
        // Form elements
        this.hostname = document.getElementById('hostname');
        this.secret = document.getElementById('secret');
        this.apiKey = document.getElementById('apiKey');
        
        // Debug secret field
        console.log('Secret field element:', this.secret);
        if (this.secret) {
            console.log('Secret field found, current value:', this.secret.value);
        } else {
            console.error('Secret field not found!');
        }
        this.embedType = document.getElementById('embedType');
        this.contentPath = document.getElementById('contentPath');
        this.externalId = document.getElementById('externalId');
        this.name = document.getElementById('name');
        this.email = document.getElementById('email');
        this.entity = document.getElementById('entity');
        this.mode = document.getElementById('mode');
        this.theme = document.getElementById('theme');
        this.prefersDark = document.getElementById('prefersDark');
        this.linkAccess = document.getElementById('linkAccess');
        this.userAttributes = document.getElementById('userAttributes');
        this.connectionRoles = document.getElementById('connectionRoles');
        this.filterSearchParam = document.getElementById('filterSearchParam');
        this.groups = document.getElementById('groups');

        // Action elements
        this.generateUrlBtn = document.getElementById('generateUrl');
        this.clearFormBtn = document.getElementById('clearForm');
        this.generatedUrl = document.getElementById('generatedUrl');
        this.copyUrlBtn = document.getElementById('copyUrl');
        this.embedFrame = document.getElementById('embedFrame');
        this.loadEmbedBtn = document.getElementById('loadEmbed');
        this.refreshEmbedBtn = document.getElementById('refreshEmbed');
        this.urlParams = document.getElementById('urlParams');
        this.signatureData = document.getElementById('signatureData');
        this.debugInfo = document.getElementById('debugInfo');
        this.iframeError = document.getElementById('iframeError');
        this.openInNewTabBtn = document.getElementById('openInNewTab');
        this.testButton = document.getElementById('testButton');
        
        // Check if critical elements are found
        if (!this.generateUrlBtn) {
            console.error('Generate URL button not found!');
        } else {
            console.log('Generate URL button found');
        }
        
        if (!this.hostname) {
            console.error('Hostname input not found!');
        } else {
            console.log('Hostname input found');
        }
        
        console.log('All elements initialized');
    }

    bindEvents() {
        console.log('Binding events...');
        
        this.generateUrlBtn.addEventListener('click', (e) => {
            console.log('Generate URL button clicked via event listener');
            e.preventDefault();
            this.generateUrl();
        });
        
        this.clearFormBtn.addEventListener('click', () => this.clearForm());
        this.copyUrlBtn.addEventListener('click', () => this.copyUrl());
        this.loadEmbedBtn.addEventListener('click', () => this.loadEmbed());
        this.refreshEmbedBtn.addEventListener('click', () => this.refreshEmbed());
        this.openInNewTabBtn.addEventListener('click', () => this.openInNewTab());
        this.testButton.addEventListener('click', () => this.testFunction());

        // Preset buttons
        document.querySelectorAll('.preset-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.loadPreset(e.target.dataset.preset));
        });

        // Auto-generate URL when embed type changes
        this.embedType.addEventListener('change', () => this.generateUrl());
        
        console.log('Events bound successfully');
    }

    loadPresets() {
        this.presets = {
            basic: {
                contentPath: '/dashboards/12345678',
                externalId: 'basic-user-001',
                name: 'Basic User',
                email: 'basic@example.com',
                entity: 'Test Company',
                mode: 'APPLICATION',
                theme: '',
                prefersDark: '',
                linkAccess: '',
                userAttributes: '{"department": "general", "access_level": "basic"}',
                connectionRoles: '{"YOUR_CONNECTION_ID": "RESTRICTED_QUERIER"}',
                filterSearchParam: '',
                groups: '["general-users"]'
            },
            admin: {
                contentPath: '/dashboards/12345678',
                externalId: 'admin-user-001',
                name: 'Admin User',
                email: 'admin@example.com',
                entity: 'Test Company',
                mode: 'APPLICATION',
                theme: '',
                prefersDark: '',
                linkAccess: '__omni_link_access_open',
                userAttributes: '{"department": "admin", "access_level": "admin", "permissions": "full"}',
                connectionRoles: '{"YOUR_CONNECTION_ID": "FULL_ACCESS"}',
                filterSearchParam: '',
                groups: '["admin-team", "managers"]'
            },
            restricted: {
                contentPath: '/dashboards/12345678',
                externalId: 'restricted-user-001',
                name: 'Restricted User',
                email: 'restricted@example.com',
                entity: 'Test Company',
                mode: 'SINGLE_CONTENT',
                theme: '',
                prefersDark: '',
                linkAccess: '',
                userAttributes: '{"department": "sales", "access_level": "restricted", "region": "west"}',
                connectionRoles: '{"YOUR_CONNECTION_ID": "RESTRICTED_QUERIER"}',
                filterSearchParam: 'f--users.region=west',
                groups: '["sales-team"]'
            },
            dark: {
                contentPath: '/dashboards/12345678',
                externalId: 'dark-user-001',
                name: 'Dark Theme User',
                email: 'dark@example.com',
                entity: 'Test Company',
                mode: 'APPLICATION',
                theme: 'vibes',
                prefersDark: 'true',
                linkAccess: '',
                userAttributes: '{"theme_preference": "dark", "department": "design"}',
                connectionRoles: '{"YOUR_CONNECTION_ID": "RESTRICTED_QUERIER"}',
                filterSearchParam: '',
                groups: '["design-team"]'
            },
            workbook: {
                contentPath: '/w/12345678',
                externalId: 'workbook-user-001',
                name: 'Workbook User',
                email: 'workbook@example.com',
                entity: 'Test Company',
                mode: 'SINGLE_CONTENT',
                theme: '',
                prefersDark: '',
                linkAccess: '',
                userAttributes: '{"department": "analytics", "can_edit": true}',
                connectionRoles: '{"YOUR_CONNECTION_ID": "EDITOR"}',
                filterSearchParam: '',
                groups: '["analytics-team"]'
            }
        };
    }

    loadPreset(presetName) {
        const preset = this.presets[presetName];
        if (!preset) return;

        // Fields to preserve (don't overwrite these)
        const preserveFields = ['hostname', 'secret', 'apiKey'];
        
        // Store current values for fields we want to preserve
        const preservedValues = {};
        preserveFields.forEach(field => {
            const element = document.getElementById(field);
            if (element) {
                preservedValues[field] = element.value;
            }
        });

        // Apply preset values
        Object.keys(preset).forEach(key => {
            const element = document.getElementById(key);
            if (element && !preserveFields.includes(key)) {
                element.value = preset[key];
            }
        });

        // Restore preserved values
        Object.keys(preservedValues).forEach(field => {
            const element = document.getElementById(field);
            if (element && preservedValues[field]) {
                element.value = preservedValues[field];
            }
        });

        this.generateUrl();
    }

    async generateUrl() {
        console.log('Generate URL button clicked');
        
        try {
            console.log('Collecting parameters...');
            const params = this.collectParameters();
            console.log('Parameters collected:', params);
            
            console.log('Validating parameters...');
            this.validateParameters(params);
            console.log('Parameters validated successfully');

            let url;
            if (this.embedType.value === '2step') {
                console.log('Generating 2-step URL...');
                url = this.generate2StepUrl(params);
            } else {
                console.log('Generating standard URL...');
                url = await this.generateStandardUrl(params);
            }

            console.log('URL generated:', url);
            this.generatedUrl.value = url;
            this.displayDebugInfo(params);
            this.showSuccess('URL generated successfully!');
        } catch (error) {
            console.error('Error in generateUrl:', error);
            let errorMessage = 'Error generating URL: ' + error.message;
            
            // Provide specific guidance for common errors
            if (error.message.includes('One-time secret not found') || error.message.includes('secret')) {
                errorMessage = 'Secret key error: Please verify your embed secret key from Admin > Embed in your Omni instance. The secret may be incorrect or expired.';
            }
            
            this.showError(errorMessage);
            console.error('URL generation error:', error);
        }
    }

    collectParameters() {
        const params = {
            hostname: this.hostname.value.trim(),
            secret: this.secret.value.trim(),
            apiKey: this.apiKey.value.trim(),
            contentPath: this.contentPath.value.trim(),
            externalId: this.externalId.value.trim(),
            name: this.name.value.trim(),
            email: this.email.value.trim(),
            entity: this.entity.value.trim(),
            mode: this.mode.value,
            theme: this.theme.value,
            prefersDark: this.prefersDark.value,
            linkAccess: this.linkAccess.value,
            userAttributes: this.parseJson(this.userAttributes.value),
            connectionRoles: this.parseJson(this.connectionRoles.value),
            filterSearchParam: this.filterSearchParam.value.trim(),
            groups: this.parseJson(this.groups.value)
        };
        
        // Debug logging for secret field
        console.log('Secret field value:', this.secret.value);
        console.log('Secret field length:', this.secret.value.length);
        console.log('Secret after trim:', params.secret);
        console.log('Secret after trim length:', params.secret.length);
        
        return params;
    }

    parseJson(jsonString) {
        if (!jsonString.trim()) return null;
        try {
            return JSON.parse(jsonString);
        } catch (error) {
            throw new Error(`Invalid JSON: ${jsonString}`);
        }
    }

    validateParameters(params) {
        console.log('Validating parameters:', params);
        
        if (!params.hostname) throw new Error('Hostname is required');
        if (!params.secret) {
            console.error('Secret is empty or undefined:', params.secret);
            throw new Error('Secret is required');
        }
        if (!params.contentPath) throw new Error('Content path is required');
        if (!params.externalId) throw new Error('External ID is required');
        if (!params.name) throw new Error('Name is required');

        // Validate secret format
        if (params.secret && params.secret.length < 32) {
            throw new Error('Secret key appears to be too short. Please check your embed secret from Admin > Embed in Omni.');
        }

        if (this.embedType.value === '2step' && !params.apiKey) {
            throw new Error('API Key is required for 2-step SSO');
        }

        // Validate connection roles if provided
        if (params.connectionRoles) {
            try {
                let connectionRolesObj;
                
                // Handle different types of connectionRoles
                if (typeof params.connectionRoles === 'string') {
                    // If it's a string, check if it's not empty
                    if (!params.connectionRoles.trim()) {
                        return; // Skip validation if empty string
                    }
                    
                    // Try to parse the string as JSON
                    try {
                        connectionRolesObj = JSON.parse(params.connectionRoles);
                    } catch (parseError) {
                        // If that fails, try URL decoding first
                        try {
                            const decoded = decodeURIComponent(params.connectionRoles);
                            connectionRolesObj = JSON.parse(decoded);
                        } catch (decodeError) {
                            throw new Error('Connection Roles must be valid JSON format. Example: {"connection-id": "RESTRICTED_QUERIER"}');
                        }
                    }
                } else if (typeof params.connectionRoles === 'object') {
                    // If it's already an object, use it directly
                    connectionRolesObj = params.connectionRoles;
                } else {
                    return; // Skip validation if not string or object
                }
                
                // Validate the connection roles object
                for (const [connectionId, role] of Object.entries(connectionRolesObj)) {
                    if (connectionId === 'YOUR_CONNECTION_ID' || connectionId === 'abcd1234-abcd-efgh-ijkl-abcdef123456') {
                        throw new Error('Please replace "YOUR_CONNECTION_ID" with your actual connection ID from Omni Settings > Connections');
                    }
                    // Check for common typos
                    if (connectionId.includes('aaa82ca0a')) {
                        throw new Error('Invalid connection ID detected. Please check for typos - it should be "aa82ca0a" not "aaa82ca0a"');
                    }
                }
            } catch (error) {
                if (error.message.includes('YOUR_CONNECTION_ID') || error.message.includes('Invalid connection ID')) {
                    throw error;
                }
                throw new Error('Connection Roles must be valid JSON format. Example: {"connection-id": "RESTRICTED_QUERIER"}');
            }
        }
    }

    async generateStandardUrl(params) {
        // Use our local API proxy to call Omni's API
        console.log('Using Omni API via local proxy');
        return await this.generateUrlViaAPI(params);
    }

    async generateUrlViaAPI(params) {
        console.log('Generating URL via local API proxy...');
        
        // Use our local proxy instead of calling Omni directly
        const proxyUrl = '/api/generate-url';
        
        // Prepare the request body according to Omni's API spec
        const requestBody = {
            hostname: params.hostname,
            contentPath: params.contentPath,
            externalId: params.externalId,
            name: params.name,
            secret: params.secret
        };

        // Add optional parameters
        if (params.email) requestBody.email = params.email;
        if (params.entity) requestBody.entity = params.entity;
        if (params.mode) requestBody.mode = params.mode;
        if (params.theme) requestBody.theme = params.theme;
        if (params.prefersDark) requestBody.prefersDark = params.prefersDark;
        if (params.linkAccess) requestBody.linkAccess = params.linkAccess;
        if (params.filterSearchParam) requestBody.filterSearchParam = params.filterSearchParam;
        
        // JSON parameters need to be URL encoded
        if (params.userAttributes && typeof params.userAttributes === 'string' && params.userAttributes.trim()) {
            try {
                const userAttributesObj = JSON.parse(params.userAttributes);
                requestBody.userAttributes = encodeURIComponent(JSON.stringify(userAttributesObj));
            } catch (error) {
                console.warn('Invalid userAttributes JSON, skipping:', error.message);
            }
        } else if (params.userAttributes && typeof params.userAttributes === 'object') {
            requestBody.userAttributes = encodeURIComponent(JSON.stringify(params.userAttributes));
        }
        
        if (params.connectionRoles && typeof params.connectionRoles === 'string' && params.connectionRoles.trim()) {
            try {
                const connectionRolesObj = JSON.parse(params.connectionRoles);
                requestBody.connectionRoles = encodeURIComponent(JSON.stringify(connectionRolesObj));
            } catch (error) {
                console.warn('Invalid connectionRoles JSON, skipping:', error.message);
            }
        } else if (params.connectionRoles && typeof params.connectionRoles === 'object') {
            requestBody.connectionRoles = encodeURIComponent(JSON.stringify(params.connectionRoles));
        }
        
        if (params.groups && typeof params.groups === 'string' && params.groups.trim()) {
            try {
                const groupsArray = JSON.parse(params.groups);
                requestBody.groups = encodeURIComponent(JSON.stringify(groupsArray));
            } catch (error) {
                console.warn('Invalid groups JSON, skipping:', error.message);
            }
        } else if (params.groups && Array.isArray(params.groups)) {
            requestBody.groups = encodeURIComponent(JSON.stringify(params.groups));
        }

        console.log('Proxy Request URL:', proxyUrl);
        console.log('Proxy Request Body:', requestBody);

        try {
            const response = await fetch(proxyUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(`API request failed: ${response.status} ${response.statusText} - ${errorData.details || errorData.error}`);
            }

            const result = await response.json();
            console.log('API Response:', result);
            
            if (result.url) {
                console.log('✅ Generated URL via Omni API:', result.url);
                return result.url;
            } else {
                throw new Error('API response did not contain a URL');
            }

        } catch (error) {
            console.error('❌ Error calling Omni API via proxy:', error);
            throw new Error(`Failed to generate URL via API: ${error.message}`);
        }
    }

    async generateStandardUrlFallback(params) {
        console.log('Using fallback URL generation');
        
        const baseUrl = `https://${params.hostname}/embed/login`;
        const urlParams = new URLSearchParams();

        // Generate nonce (must be exactly 32 characters)
        const nonce = this.generateNonce();
        
        // Validate nonce length
        if (nonce.length !== 32) {
            throw new Error(`Nonce generation failed: expected 32 characters, got ${nonce.length}`);
        }

        // Required parameters
        urlParams.set('contentPath', params.contentPath);
        urlParams.set('externalId', params.externalId);
        urlParams.set('name', params.name);
        urlParams.set('nonce', nonce);

        // Optional parameters
        if (params.email) urlParams.set('email', params.email);
        if (params.entity) urlParams.set('entity', params.entity);
        if (params.mode) urlParams.set('mode', params.mode);
        if (params.theme) urlParams.set('theme', params.theme);
        if (params.prefersDark) urlParams.set('prefersDark', params.prefersDark);
        if (params.linkAccess) urlParams.set('linkAccess', params.linkAccess);
        if (params.filterSearchParam) urlParams.set('filterSearchParam', params.filterSearchParam);

        // JSON parameters
        if (params.userAttributes) {
            urlParams.set('userAttributes', encodeURIComponent(JSON.stringify(params.userAttributes)));
        }
        if (params.connectionRoles) {
            urlParams.set('connectionRoles', encodeURIComponent(JSON.stringify(params.connectionRoles)));
        }
        if (params.groups) {
            urlParams.set('groups', encodeURIComponent(JSON.stringify(params.groups)));
        }

        // Generate signature using fallback method
        const signature = await this.generateSignatureFallback(params, baseUrl, urlParams, nonce);
        urlParams.set('signature', signature);

        return `${baseUrl}?${urlParams.toString()}`;
    }

    async generateSignatureFallback(params, baseUrl, urlParams, nonce) {
        // Create the signature string according to Omni's specification
        // The signature string should be: baseUrl\ncontentPath\nexternalId\nname\nnonce\n[optional params in alphabetical order]
        const signatureParts = [
            baseUrl,
            params.contentPath,
            params.externalId,
            params.name,
            nonce
        ];

        // Add optional parameters in alphabetical order
        const optionalParams = [];
        if (params.email) optionalParams.push(['email', params.email]);
        if (params.entity) optionalParams.push(['entity', params.entity]);
        if (params.mode) optionalParams.push(['mode', params.mode]);
        if (params.theme) optionalParams.push(['theme', params.theme]);
        if (params.prefersDark) optionalParams.push(['prefersDark', params.prefersDark]);
        if (params.linkAccess) optionalParams.push(['linkAccess', params.linkAccess]);
        if (params.filterSearchParam) optionalParams.push(['filterSearchParam', params.filterSearchParam]);
        if (params.userAttributes) optionalParams.push(['userAttributes', JSON.stringify(params.userAttributes)]);
        if (params.connectionRoles) optionalParams.push(['connectionRoles', JSON.stringify(params.connectionRoles)]);
        if (params.groups) optionalParams.push(['groups', JSON.stringify(params.groups)]);

        // Sort optional parameters alphabetically
        optionalParams.sort((a, b) => a[0].localeCompare(b[0]));

        // Add to signature parts
        optionalParams.forEach(([key, value]) => {
            signatureParts.push(value);
        });

        const signatureString = signatureParts.join('\n');
        
        console.log('=== FALLBACK SIGNATURE DEBUG ===');
        console.log('Signature string:', JSON.stringify(signatureString));
        console.log('Secret used:', params.secret.substring(0, 8) + '...');
        
        try {
            // Use Web Crypto API for proper HMAC-SHA256
            const encoder = new TextEncoder();
            const keyData = encoder.encode(params.secret);
            const messageData = encoder.encode(signatureString);
            
            // Import the secret as a key
            const key = await crypto.subtle.importKey(
                'raw',
                keyData,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            
            // Sign the message
            const signature = await crypto.subtle.sign('HMAC', key, messageData);
            
            // Convert to base64url
            const base64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
            const base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            
            console.log('Generated HMAC-SHA256 signature:', base64url);
            console.log('Signature length:', base64url.length);
            console.log('=== END FALLBACK DEBUG ===');
            
            return base64url;
            
        } catch (error) {
            console.error('Web Crypto API failed, using simple fallback:', error);
            
            // Fallback to simple hash if Web Crypto API fails
            let hash = 0;
            for (let i = 0; i < signatureString.length; i++) {
                const char = signatureString.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash;
            }
            
            // Add secret to the hash
            for (let i = 0; i < params.secret.length; i++) {
                const char = params.secret.charCodeAt(i);
                hash = ((hash << 2) - hash) + char;
                hash = hash & hash;
            }
            
            // Create a 32-character signature
            const hashString = Math.abs(hash).toString(16) + nonce.substring(0, 16);
            let signature = hashString;
            while (signature.length < 32) {
                signature += Math.random().toString(36).substring(2);
            }
            signature = signature.substring(0, 32);
            
            console.log('Generated simple fallback signature:', signature);
            console.log('Signature length:', signature.length);
            console.log('=== END FALLBACK DEBUG ===');
            
            return signature;
        }
    }

    generate2StepUrl(params) {
        // For 2-step SSO, we'll generate the session first, then the redemption URL
        // This is a simplified version - in production, you'd make the API call
        const sessionId = this.generateSessionId();
        const baseUrl = `https://${params.hostname}/embed/sso/redeem-session`;
        const redemptionParams = new URLSearchParams();

        redemptionParams.set('sessionId', sessionId);
        redemptionParams.set('nonce', this.generateNonce());

        if (params.theme) redemptionParams.set('theme', params.theme);
        if (params.prefersDark) redemptionParams.set('prefersDark', params.prefersDark);

        // Generate signature for redemption
        const signature = this.generateRedemptionSignature(params, baseUrl, redemptionParams);
        redemptionParams.set('signature', signature);

        return `${baseUrl}?${redemptionParams.toString()}`;
    }

    generateSignature(params, baseUrl, urlParams, nonce) {
        // Create the signature string according to Omni's specification
        // Order: login URL, content path, external id, name, nonce, then optional params alphabetically
        // Note: According to Omni docs, the order is:
        // 1. login URL
        // 2. content path  
        // 3. external id
        // 4. name
        // 5. nonce
        // 6. optional parameters in alphabetical order
        const signatureParts = [
            baseUrl,
            params.contentPath,
            params.externalId,
            params.name,
            nonce
        ];

        // Add optional parameters in alphabetical order
        const optionalParams = [];
        if (params.email) optionalParams.push(['email', params.email]);
        if (params.entity) optionalParams.push(['entity', params.entity]);
        if (params.mode) optionalParams.push(['mode', params.mode]);
        if (params.theme) optionalParams.push(['theme', params.theme]);
        if (params.prefersDark) optionalParams.push(['prefersDark', params.prefersDark]);
        if (params.linkAccess) optionalParams.push(['linkAccess', params.linkAccess]);
        if (params.filterSearchParam) optionalParams.push(['filterSearchParam', params.filterSearchParam]);
        if (params.userAttributes) optionalParams.push(['userAttributes', JSON.stringify(params.userAttributes)]);
        if (params.connectionRoles) optionalParams.push(['connectionRoles', JSON.stringify(params.connectionRoles)]);
        if (params.groups) optionalParams.push(['groups', JSON.stringify(params.groups)]);

        // Sort optional parameters alphabetically
        optionalParams.sort((a, b) => a[0].localeCompare(b[0]));

        // Add to signature parts
        optionalParams.forEach(([key, value]) => {
            signatureParts.push(value);
        });

        const signatureString = signatureParts.join('\n');
        
        // Debug logging
        console.log('=== SIGNATURE DEBUG ===');
        console.log('Signature parts:', signatureParts);
        console.log('Signature string (with \\n):', JSON.stringify(signatureString));
        console.log('Signature string (raw):', signatureString);
        console.log('Secret length:', params.secret.length);
        console.log('Secret preview:', params.secret.substring(0, 8) + '...');
        console.log('Base URL:', baseUrl);
        console.log('Content Path:', params.contentPath);
        console.log('External ID:', params.externalId);
        console.log('Name:', params.name);
        console.log('Nonce:', nonce);
        console.log('=== END SIGNATURE DEBUG ===');
        
        return this.createHmacSignature(signatureString, params.secret);
    }

    generateRedemptionSignature(params, baseUrl, urlParams) {
        const signatureParts = [
            baseUrl,
            urlParams.get('nonce'),
            urlParams.get('sessionId')
        ];

        // Add optional parameters
        if (params.theme) signatureParts.push(params.theme);
        if (params.prefersDark) signatureParts.push(params.prefersDark);

        const signatureString = signatureParts.join('\n');
        return this.createHmacSignature(signatureString, params.secret);
    }

    createHmacSignature(data, secret) {
        try {
            // Ensure CryptoJS is available
            if (typeof CryptoJS === 'undefined') {
                throw new Error('CryptoJS not available');
            }
            
            // Test with a known value first
            const testData = 'test';
            const testSecret = 'secret';
            const testHash = CryptoJS.HmacSHA256(testData, testSecret);
            const testBase64 = CryptoJS.enc.Base64.stringify(testHash);
            console.log('CryptoJS test - data:', testData, 'secret:', testSecret, 'result:', testBase64);
            
            // Using CryptoJS for HMAC-SHA256
            const hash = CryptoJS.HmacSHA256(data, secret);
            const base64url = CryptoJS.enc.Base64url.stringify(hash);
            
            console.log('=== HMAC SIGNATURE DEBUG ===');
            console.log('Data being signed:', JSON.stringify(data));
            console.log('Secret being used:', secret.substring(0, 8) + '...');
            console.log('HMAC-SHA256 result (hex):', hash.toString(CryptoJS.enc.Hex));
            console.log('Base64url result:', base64url);
            console.log('=== END HMAC DEBUG ===');
            
            return base64url;
        } catch (error) {
            console.error('CryptoJS error:', error);
            throw new Error('CryptoJS is required for signature generation. Please ensure the library loads properly.');
        }
    }

    generateSessionId() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    generateNonce() {
        // Generate exactly 32 characters for nonce
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < 32; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    displayDebugInfo(params) {
        // Display URL parameters
        const generatedUrlParams = new URLSearchParams(this.generatedUrl.value.split('?')[1] || '');
        const paramObj = {};
        for (const [key, value] of generatedUrlParams) {
            paramObj[key] = value;
        }
        this.urlParams.textContent = JSON.stringify(paramObj, null, 2);

        // Display signature data
        const signatureInfo = {
            embedType: this.embedType.value,
            hostname: params.hostname,
            contentPath: params.contentPath,
            externalId: params.externalId,
            name: params.name,
            hasSecret: !!params.secret,
            hasApiKey: !!params.apiKey
        };
        this.signatureData.textContent = JSON.stringify(signatureInfo, null, 2);

        // Display debug information
        const debugUrlParams = new URLSearchParams(this.generatedUrl.value.split('?')[1] || '');
        const nonce = debugUrlParams.get('nonce') || 'Not found';
        
        const debugInfo = {
            secretLength: params.secret ? params.secret.length : 0,
            secretPreview: params.secret ? params.secret.substring(0, 8) + '...' : 'Not set',
            nonceLength: nonce.length,
            noncePreview: nonce.length > 0 ? nonce.substring(0, 8) + '...' : 'Not generated',
            nonceValid: nonce.length === 32,
            signatureMethod: 'HMAC-SHA256 with Base64url',
            urlGenerated: new Date().toISOString()
        };
        this.debugInfo.textContent = JSON.stringify(debugInfo, null, 2);
    }

    loadEmbed() {
        const url = this.generatedUrl.value;
        if (!url || url === 'about:blank') {
            this.showError('Please generate a URL first');
            return;
        }

        console.log('🔄 Loading embed with URL:', url);
        console.log('🌐 Current browser:', navigator.userAgent);
        console.log('🍪 Cookies enabled:', navigator.cookieEnabled);
        console.log('🔒 Secure context:', window.isSecureContext);
        console.log('📍 Current origin:', window.location.origin);
        console.log('🔗 Current URL:', window.location.href);

        // Hide any previous error messages
        this.iframeError.style.display = 'none';
        
        // Set up comprehensive error handling for iframe
        this.embedFrame.onerror = (error) => {
            console.error('❌ Iframe onerror event:', error);
            this.showIframeError('Iframe failed to load. This might be due to network issues or Omni server errors.');
        };

        // Iframe loading is now handled by loadIframeWithRetry method

        // Add additional event listeners for debugging
        this.embedFrame.addEventListener('load', () => {
            console.log('✅ Iframe load event listener fired');
        });

        this.embedFrame.addEventListener('error', (error) => {
            console.error('❌ Iframe error event listener fired:', error);
        });

        // Convert Omni URL to use our proxy
        const proxyUrl = url.replace('https://', '/proxy/');
        console.log('Using proxy URL for iframe:', proxyUrl);
        
        // Debug: Log the original URL parameters
        try {
            const urlObj = new URL(url);
            console.log('🔍 Original URL parameters:');
            urlObj.searchParams.forEach((value, key) => {
                console.log(`  ${key}: ${value}`);
            });
            
            // Check for potential issues
            const nonce = urlObj.searchParams.get('nonce');
            const signature = urlObj.searchParams.get('signature');
            const connectionRoles = urlObj.searchParams.get('connectionRoles');
            
            console.log('🔍 Parameter validation:');
            console.log(`  Nonce length: ${nonce ? nonce.length : 'missing'}`);
            console.log(`  Signature length: ${signature ? signature.length : 'missing'}`);
            console.log(`  Connection roles: ${connectionRoles ? 'present' : 'missing'}`);
            
            if (nonce && nonce.length !== 32) {
                console.warn('⚠️ Nonce length is not 32 characters:', nonce.length);
            }
            if (signature && signature.length < 32) {
                console.warn('⚠️ Signature appears too short:', signature.length);
            }
        } catch (error) {
            console.error('❌ Error parsing URL:', error);
        }
        
        // Try to load the embed with error recovery
        this.loadIframeWithRetry(proxyUrl, url);
        
        // Check for iframe loading issues after a short delay
        setTimeout(() => {
            console.log('🔍 Checking iframe status after 3 seconds...');
            try {
                // This will throw an error if X-Frame-Options blocks the iframe
                const iframeDoc = this.embedFrame.contentDocument || this.embedFrame.contentWindow.document;
                console.log('✅ Iframe content accessible:', iframeDoc ? 'Yes' : 'No');
            } catch (error) {
                // Cross-origin restrictions are expected and normal for iframe embedding
                if (error.name === 'SecurityError' && error.message.includes('cross-origin')) {
                    console.log('✅ Iframe loaded (cross-origin restrictions are normal)');
                } else if (error.message.includes('X-Frame-Options') || error.message.includes('frame-ancestors')) {
                    console.log('🚫 CSP frame-ancestors blocking detected');
                    this.showIframeError('Content Security Policy is blocking the iframe. Try opening in a new tab instead.');
                } else {
                    console.log('❓ Unknown iframe error:', error);
                    this.showIframeError('Unknown iframe error. Try opening in a new tab instead.');
                }
            }
        }, 3000);
        
        this.showSuccess('Attempting to load embed...');
    }

    refreshEmbed() {
        this.iframeError.style.display = 'none';
        this.embedFrame.src = this.embedFrame.src;
        this.showSuccess('Embed refreshed!');
    }

    showIframeError(customMessage = null) {
        this.iframeError.style.display = 'flex';
        if (customMessage) {
            // Update the error message with custom text
            const errorContent = this.iframeError.querySelector('.error-content');
            if (errorContent) {
                const errorText = errorContent.querySelector('p');
                if (errorText) {
                    errorText.textContent = customMessage;
                }
            }
        }
        this.showError('Iframe loading issue - see details below');
    }

    loadIframeWithRetry(proxyUrl, originalUrl, retryCount = 0) {
        const maxRetries = 2;
        
        console.log(`🔄 Loading iframe (attempt ${retryCount + 1}/${maxRetries + 1})`);
        
        // Set up a timeout to detect if the iframe fails to load
        const loadTimeout = setTimeout(() => {
            if (retryCount < maxRetries) {
                console.log(`⏰ Iframe load timeout, retrying with direct URL...`);
                this.embedFrame.src = originalUrl;
                this.loadIframeWithRetry(originalUrl, originalUrl, retryCount + 1);
            } else {
                console.log('❌ Iframe failed to load after all retries');
                this.showIframeError('Iframe failed to load after multiple attempts. The Omni application may have issues.');
            }
        }, 10000); // 10 second timeout
        
        // Clear timeout when iframe loads successfully
        this.embedFrame.onload = () => {
            clearTimeout(loadTimeout);
            console.log('✅ Iframe loaded successfully');
            
            // Set up error boundary for React errors
            this.setupIframeErrorBoundary();
            
                        // Check if the iframe actually loaded content successfully
                        setTimeout(() => {
                            try {
                                const iframeDoc = this.embedFrame.contentDocument || this.embedFrame.contentWindow.document;
                                if (iframeDoc && iframeDoc.body && iframeDoc.body.innerHTML.trim()) {
                                    console.log('✅ Iframe content loaded successfully');
                                    this.showSuccess('🎉 Omni Analytics embedded successfully! You can now test different parameters.');
                                } else {
                                    console.log('⚠️ Iframe loaded but content appears empty');
                                    this.showIframeError('Iframe loaded but content appears empty. This might indicate an error in the Omni application.');
                                }
                            } catch (error) {
                                // Cross-origin restrictions are normal and expected
                                console.log('✅ Iframe loaded (cross-origin restrictions are normal)');
                                this.showSuccess('🎉 Omni Analytics embedded successfully! You can now test different parameters.');
                            }
                        }, 1000);
        };
        
        // Set the iframe source
        this.embedFrame.src = proxyUrl;
    }

    setupIframeErrorBoundary() {
        // Set up global error handling for the iframe
        window.addEventListener('message', (event) => {
            if (event.source === this.embedFrame.contentWindow) {
                if (event.data && event.data.type === 'react-error') {
                    console.log('🔍 React error detected in iframe:', event.data.error);
                    this.showIframeError('React error detected in Omni application. This may be due to parameter issues or Omni application bugs.');
                }
            }
        });
    }

    checkForReactErrors() {
        // Monitor for React errors in the iframe
        try {
            const iframeWindow = this.embedFrame.contentWindow;
            if (iframeWindow) {
                // Override console.error to catch React errors
                const originalError = iframeWindow.console.error;
                iframeWindow.console.error = (...args) => {
                    const errorMessage = args.join(' ');
                    
                    // Filter out common Omni application errors that are not critical
                    if (errorMessage.includes('React error #418') || 
                        errorMessage.includes('React error #423') ||
                        errorMessage.includes('Sentry') ||
                        errorMessage.includes('sentry.io') ||
                        errorMessage.includes('Minified React error')) {
                        // These are expected errors from Omni's application
                        return; // Don't log these at all
                    }
                    
                    // Call original error function for other errors
                    originalError.apply(iframeWindow.console, args);
                };
            }
        } catch (error) {
            // Cross-origin restrictions prevent access
            console.log('Cannot monitor iframe console due to cross-origin restrictions');
        }
    }

    openInNewTab() {
        const url = this.generatedUrl.value;
        if (!url || url === 'about:blank') {
            this.showError('Please generate a URL first');
            return;
        }

        window.open(url, '_blank', 'noopener,noreferrer');
        this.showSuccess('Opened in new tab!');
    }

    copyUrl() {
        const url = this.generatedUrl.value;
        if (!url) {
            this.showError('No URL to copy');
            return;
        }

        navigator.clipboard.writeText(url).then(() => {
            this.showSuccess('URL copied to clipboard!');
        }).catch(() => {
            this.showError('Failed to copy URL');
        });
    }

    clearForm() {
        // Only clear the output areas, keep form data intact
        this.generatedUrl.value = '';
        this.embedFrame.src = 'about:blank';
        this.urlParams.textContent = '';
        this.signatureData.textContent = '';

        this.showSuccess('Output cleared!');
    }

    showSuccess(message) {
        this.showNotification(message, 'success');
    }

    showError(message) {
        this.showNotification(message, 'error');
    }

    testFunction() {
        console.log('Test button clicked!');
        
        // Test with the official Omni SDK
        if (typeof window.OmniEmbed === 'undefined') {
            alert('Omni SDK not loaded! Check console for details.');
            console.error('Omni Embed SDK not available');
            return;
        }
        
        // Test SDK with known values
        const testParams = {
            contentId: '12345678',
            externalId: 'test-user-001',
            name: 'Test User',
            organizationName: 'example',
            secret: 'test-secret-key-32-chars-long-12345',
            email: 'test@example.com',
            theme: 'vibes'
        };
        
        console.log('=== TESTING OMNISDK ===');
        console.log('Test parameters:', testParams);
        
        try {
            const testUrl = window.OmniEmbed.embedSsoDashboard(testParams);
            console.log('Test URL generated:', testUrl);
            alert('SDK test completed! Check console for details.');
        } catch (error) {
            console.error('SDK test failed:', error);
            alert('SDK test failed! Check console for errors.');
        }
        
        this.showSuccess('SDK test completed! Check console for details.');
    }

    showNotification(message, type) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            z-index: 1000;
            animation: slideIn 0.3s ease;
            max-width: 300px;
            word-wrap: break-word;
        `;

        if (type === 'success') {
            notification.style.background = 'linear-gradient(135deg, #48bb78, #38a169)';
        } else {
            notification.style.background = 'linear-gradient(135deg, #f56565, #e53e3e)';
        }

        document.body.appendChild(notification);

        // Remove after 3 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }
}

// Add CSS for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// App initialization is now handled in index.html after CryptoJS loads