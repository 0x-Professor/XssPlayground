/**
 * Advanced XSS Labs Helper Functions
 */

const AdvancedLabs = {
    // DOM Clobbering helpers
    domClobbering: {
        checkObjectOverride: function(obj, prop) {
            return obj && obj[prop] !== undefined;
        },
        
        verifyPropertyCollision: function(elementId, expectedProp) {
            const element = document.getElementById(elementId);
            return element && element[expectedProp] !== undefined;
        }
    },
    
    // CSP Bypass helpers
    cspBypass: {
        verifyScriptExecution: function(marker) {
            return window[marker] === true;
        },
        
        checkDynamicScriptLoad: function(url) {
            return new Promise((resolve, reject) => {
                const script = document.createElement('script');
                script.src = url;
                script.onload = () => resolve(true);
                script.onerror = () => reject(false);
                document.body.appendChild(script);
            });
        }
    },
    
    // Framework-specific XSS helpers
    frameworkXSS: {
        reactTemplateCheck: function(input) {
            return input.includes('dangerouslySetInnerHTML');
        },
        
        angularTemplateCheck: function(input) {
            return input.includes('ng-') || input.includes('[(') || input.includes(')]');
        },
        
        vueTemplateCheck: function(input) {
            return input.includes('v-html') || input.includes('v-bind');
        }
    },
    
    // Polyglot XSS helpers
    polyglot: {
        testMultiContext: function(payload) {
            const contexts = {
                html: this.testHTMLContext(payload),
                attribute: this.testAttributeContext(payload),
                javascript: this.testJavaScriptContext(payload),
                css: this.testCSSContext(payload)
            };
            
            return Object.values(contexts).every(result => result === true);
        },
        
        testHTMLContext: function(payload) {
            const div = document.createElement('div');
            div.innerHTML = payload;
            return div.querySelector('script') !== null;
        },
        
        testAttributeContext: function(payload) {
            const div = document.createElement('div');
            div.setAttribute('data-test', payload);
            return div.onclick !== null;
        },
        
        testJavaScriptContext: function(payload) {
            try {
                return eval('(function(){' + payload + '})()') === true;
            } catch (e) {
                return false;
            }
        },
        
        testCSSContext: function(payload) {
            const style = document.createElement('style');
            style.textContent = `body { color: ${payload} }`;
            return style.sheet !== null;
        }
    }
};

// Export for global access
window.AdvancedLabs = AdvancedLabs;