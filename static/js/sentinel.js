// static/js/sentinel.js
// SentinelAuth - Multi-layered Anti-Bot Defense System

(function() {
    'use strict';

    // ========================================
    // LAYER 1: BEHAVIORAL TIMING
    // ========================================
    const t_page_load = performance.now();
    let t_first_focus = 0;
    let t_first_key = 0;
    let t_submit = 0;

    // ========================================
    // LAYER 2: HEADLESS BROWSER DETECTION
    // ========================================
    function checkHeadless() {
        let score = 0;

        // Check 1: WebDriver flag (most direct indicator)
        if (navigator.webdriver === true) {
            score += 100;
        }

        // Check 2: Missing window.chrome property (common in older Puppeteer)
        if (!window.chrome && /Chrome/.test(navigator.userAgent)) {
            score += 20;
        }

        // Check 3: Check for presence of automation properties
        if (window.document.__selenium_unwrapped || window.document.__webdriver_evaluate) {
            score += 50;
        }

        // Check 4: WebGL Renderer (headless often uses SwiftShader)
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                    if (renderer && (
                        renderer.includes('SwiftShader') ||
                        renderer.includes('llvmpipe') ||
                        renderer.includes('Microsoft Basic Render')
                    )) {
                        score += 30;
                    }
                }
            }
        } catch (e) {
            score += 10;
        }

        // Check 5: Missing plugins (most modern browsers have some)
        if (navigator.plugins && navigator.plugins.length === 0) {
            score += 15;
        }

        // Check 6: Language inconsistencies
        if (!navigator.languages || navigator.languages.length === 0) {
            score += 10;
        }

        return score;
    }

    // ========================================
    // LAYER 3: BROWSER FINGERPRINTING
    // ========================================
    function generateFingerprint() {
        const components = [];

        // Screen properties
        components.push(screen.width);
        components.push(screen.height);
        components.push(screen.colorDepth);
        components.push(screen.pixelDepth);

        // Timezone
        components.push(new Date().getTimezoneOffset());

        // User agent
        components.push(navigator.userAgent);

        // Platform
        components.push(navigator.platform);

        // Hardware concurrency
        components.push(navigator.hardwareConcurrency || 'unknown');

        // Language
        components.push(navigator.language);

        // Canvas fingerprint
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('SentinelAuth', 2, 15);
            components.push(canvas.toDataURL());
        } catch (e) {
            components.push('canvas-error');
        }

        // WebGL fingerprint
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    components.push(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL));
                    components.push(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL));
                }
            }
        } catch (e) {
            components.push('webgl-error');
        }

        // Installed fonts detection (simplified)
        components.push(detectFonts());

        // Generate hash from all components
        return simpleHash(components.join('|||'));
    }

    function detectFonts() {
        const baseFonts = ['monospace', 'sans-serif', 'serif'];
        const testFonts = [
            'Arial', 'Verdana', 'Courier New', 'Times New Roman',
            'Georgia', 'Palatino', 'Garamond', 'Bookman',
            'Comic Sans MS', 'Trebuchet MS', 'Impact'
        ];

        const detectedFonts = [];
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');

        function getWidth(font) {
            ctx.font = `72px ${font}`;
            return ctx.measureText('mmmmmmmmmmlli').width;
        }

        const baseWidths = {};
        baseFonts.forEach(baseFont => {
            baseWidths[baseFont] = getWidth(baseFont);
        });

        testFonts.forEach(testFont => {
            const detected = baseFonts.some(baseFont => {
                return getWidth(`${testFont},${baseFont}`) !== baseWidths[baseFont];
            });
            if (detected) {
                detectedFonts.push(testFont);
            }
        });

        return detectedFonts.join(',');
    }

    function simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash).toString(36);
    }

    // ========================================
    // INITIALIZATION
    // ========================================
    document.addEventListener('DOMContentLoaded', () => {
        const loginForm = document.getElementById('login-form');
        const usernameField = document.getElementById('username');
        const passwordField = document.getElementById('password');

        if (!loginForm || !usernameField || !passwordField) {
            console.error('SentinelAuth: Required form elements not found');
            return;
        }

        // Track first focus
        usernameField.addEventListener('focus', () => {
            if (t_first_focus === 0) {
                t_first_focus = performance.now();
            }
        }, { once: true });

        // Track first keypress
        const trackKeypress = () => {
            if (t_first_key === 0) {
                t_first_key = performance.now();
            }
        };
        usernameField.addEventListener('keydown', trackKeypress, { once: true });
        passwordField.addEventListener('keydown', trackKeypress, { once: true });

        // Intercept form submission
        loginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            t_submit = performance.now();

            // ========================================
            // CALCULATE SCORES
            // ========================================

            // Layer 1: Behavioral Timing Score
            const total_interaction_time = t_submit - t_page_load;
            const typing_latency = t_first_key > 0 ? (t_submit - t_first_key) : 0;

            const MIN_HUMAN_INTERACTION_TIME = 800; // 800ms minimum
            const MIN_HUMAN_TYPING_LATENCY = 150; // 150ms minimum

            let timing_score = 0;
            if (total_interaction_time < MIN_HUMAN_INTERACTION_TIME) {
                timing_score += 50;
            }
            if (typing_latency > 0 && typing_latency < MIN_HUMAN_TYPING_LATENCY) {
                timing_score += 30;
            }

            // Layer 2: Headless Detection Score
            const headless_score = checkHeadless();

            // Layer 3: Browser Fingerprint
            const fingerprint = generateFingerprint();

            // ========================================
            // INJECT HIDDEN FIELDS
            // ========================================

            // Remove any existing sentinel fields
            const existingFields = loginForm.querySelectorAll('.sentinel-field');
            existingFields.forEach(field => field.remove());

            // Add timing score
            const timingInput = document.createElement('input');
            timingInput.type = 'hidden';
            timingInput.name = 'sentinel_timing';
            timingInput.className = 'sentinel-field';
            timingInput.value = timing_score;
            loginForm.appendChild(timingInput);

            // Add headless score
            const headlessInput = document.createElement('input');
            headlessInput.type = 'hidden';
            headlessInput.name = 'sentinel_headless';
            headlessInput.className = 'sentinel-field';
            headlessInput.value = headless_score;
            loginForm.appendChild(headlessInput);

            // Add fingerprint
            const fingerprintInput = document.createElement('input');
            fingerprintInput.type = 'hidden';
            fingerprintInput.name = 'sentinel_fingerprint';
            fingerprintInput.className = 'sentinel-field';
            fingerprintInput.value = fingerprint;
            loginForm.appendChild(fingerprintInput);

            // Add timing metadata for server analysis
            const metadataInput = document.createElement('input');
            metadataInput.type = 'hidden';
            metadataInput.name = 'sentinel_metadata';
            metadataInput.className = 'sentinel-field';
            metadataInput.value = JSON.stringify({
                t_load_to_submit: Math.round(total_interaction_time),
                t_first_focus: Math.round(t_first_focus - t_page_load),
                t_first_key: t_first_key > 0 ? Math.round(t_first_key - t_page_load) : null,
                t_typing_duration: typing_latency > 0 ? Math.round(typing_latency) : null
            });
            loginForm.appendChild(metadataInput);

            // Submit the form
            loginForm.submit();
        });
    });
})();
