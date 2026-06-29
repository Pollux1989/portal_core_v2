/**
 * Autho Core - Sistema de Autenticación y Seguridad
 * JavaScript principal para funcionalidades de autenticación
 */

// Función para inicializar cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', function() {
    // Inicializar componentes
    initPasswordToggle();
    initFormValidation();
    initAutoFocus();
    initCountdownTimers();
    initSecurityFeatures();
    initMessages();
});

/**
 * Inicializar funcionalidad de toggle de contraseñas
 */
function initPasswordToggle() {
    const toggleButtons = document.querySelectorAll('[id^="toggle"], [id^="password-toggle"]');

    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const inputId = this.getAttribute('data-target') ||
                          this.id.replace('toggle', '').toLowerCase();

            // Encontrar el input de contraseña
            const passwordInput = this.parentElement.querySelector('input[type="password"], input[type="text"]');

            if (passwordInput) {
                const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                passwordInput.setAttribute('type', type);

                // Actualizar icono
                const icon = this.querySelector('i');
                if (icon) {
                    icon.classList.toggle('bi-eye');
                    icon.classList.toggle('bi-eye-slash');
                }
            }
        });
    });
}

/**
 * Inicializar validación de formularios
 */
function initFormValidation() {
    const forms = document.querySelectorAll('.auth-form');

    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            // Validar campos requeridos
            const requiredFields = form.querySelectorAll('[required]');
            let isValid = true;

            requiredFields.forEach(field => {
                if (!field.value.trim()) {
                    isValid = false;
                    field.classList.add('is-invalid');
                } else {
                    field.classList.remove('is-invalid');
                }
            });

            if (!isValid) {
                e.preventDefault();
            }
        });

        // Validar contraseñas coincidentes
        const passwordFields = form.querySelectorAll('input[type="password"]');
        if (passwordFields.length >= 2) {
            const password1 = passwordFields[0];
            const password2 = passwordFields[1];

            password2.addEventListener('input', function() {
                if (this.value !== password1.value) {
                    this.setCustomValidity('Las contraseñas no coinciden');
                } else {
                    this.setCustomValidity('');
                }
            });
        }
    });
}

/**
 * Inicializar auto-focus en el primer campo del formulario
 */
function initAutoFocus() {
    const firstInput = document.querySelector('.auth-form input:not([readonly])');
    if (firstInput && !firstInput.autofocus) {
        firstInput.focus();
    }
}

/**
 * Inicializar contadores regresivos
 */
function initCountdownTimers() {
    const countdownElements = document.querySelectorAll('[data-countdown]');

    countdownElements.forEach(element => {
        let seconds = parseInt(element.getAttribute('data-countdown'), 10);

        const interval = setInterval(() => {
            seconds--;
            element.textContent = seconds;

            if (seconds <= 0) {
                clearInterval(interval);

                // Recargar o realizar acción cuando termine
                const callback = element.getAttribute('data-callback');
                if (callback && window[callback]) {
                    window[callback]();
                }
            }
        }, 1000);
    });
}

/**
 * Inicializar características de seguridad
 */
function initSecurityFeatures() {
    // Detectar cambios de dispositivo
    const deviceFingerprint = generateDeviceFingerprint();
    sessionStorage.setItem('device_fingerprint', deviceFingerprint);

    // Establecer timeout de sesión
    initSessionTimeout();

    // Prevenir múltiples envíos de formularios
    preventMultipleSubmissions();
}

/**
 * Generar fingerprint del dispositivo
 */
function generateDeviceFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const txt = 'device_fingerprint';
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText(txt, 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText(txt, 4, 17);

    const fingerprint = canvas.toDataURL();
    return btoa(fingerprint);
}

/**
 * Inicializar timeout de sesión
 */
function initSessionTimeout() {
    const timeoutMinutes = parseInt(
        document.body.getAttribute('data-session-timeout') || '30',
        10
    );

    if (timeoutMinutes > 0) {
        let timeoutSeconds = timeoutMinutes * 60;
        let warningShown = false;

        // Reset timer on activity
        const resetTimer = () => {
            timeoutSeconds = timeoutMinutes * 60;
            warningShown = false;
        };

        ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
            document.addEventListener(event, resetTimer);
        });

        // Check timeout every second
        setInterval(() => {
            timeoutSeconds--;

            if (timeoutSeconds <= 60 && !warningShown) {
                warningShown = true;
                showSessionWarning();
            }

            if (timeoutSeconds <= 0) {
                window.location.href = '/logout/?timeout=true';
            }
        }, 1000);
    }
}

/**
 * Mostrar advertencia de sesión
 */
function showSessionWarning() {
    const warning = document.createElement('div');
    warning.className = 'alert alert-warning session-warning';
    warning.innerHTML = `
        <i class="bi bi-exclamation-triangle-fill"></i>
        <strong>Tu sesión está a punto de expirar.</strong>
        <button class="btn btn-primary btn-sm" onclick="this.parentElement.remove();">Continuar</button>
    `;
    document.body.appendChild(warning);
}

/**
 * Prevenir múltiples envíos de formularios
 */
function preventMultipleSubmissions() {
    const forms = document.querySelectorAll('.auth-form');

    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const submitButton = form.querySelector('button[type="submit"]');

            if (submitButton && submitButton.classList.contains('btn-loading')) {
                e.preventDefault();
                return;
            }

            if (submitButton) {
                submitButton.classList.add('btn-loading');
                submitButton.disabled = true;
            }
        });
    });
}

/**
 * Inicializar manejo de mensajes
 */
function initMessages() {
    // Auto-hide success messages
    const successMessages = document.querySelectorAll('.alert-success');

    successMessages.forEach(message => {
        setTimeout(() => {
            message.style.opacity = '0';
            message.style.transition = 'opacity 0.5s';

            setTimeout(() => {
                message.remove();
            }, 500);
        }, 5000);
    });

    // Close button functionality
    const closeButtons = document.querySelectorAll('.alert .btn-close');

    closeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const alert = this.closest('.alert');
            alert.style.opacity = '0';
            alert.style.transition = 'opacity 0.5s';

            setTimeout(() => {
                alert.remove();
            }, 500);
        });
    });
}

/**
 * Validar fortaleza de contraseña
 */
function validatePasswordStrength(password) {
    const requirements = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
    };

    const score = Object.values(requirements).filter(Boolean).length;
    const levels = ['Muy débil', 'Débil', 'Media', 'Fuerte', 'Muy fuerte'];

    return {
        requirements,
        score,
        level: levels[score - 1] || 'Muy débil'
    };
}

/**
 * Mostrar indicador de fortaleza de contraseña
 */
function showPasswordStrength(password, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const strength = validatePasswordStrength(password);

    // Actualizar requisitos
    Object.keys(strength.requirements).forEach(key => {
        const element = document.getElementById(`req-${key}`);
        if (element) {
            if (strength.requirements[key]) {
                element.classList.add('text-success');
                element.classList.remove('text-muted');
            } else {
                element.classList.remove('text-success');
                element.classList.add('text-muted');
            }
        }
    });

    // Actualizar indicador general
    const indicator = document.getElementById('password-strength-indicator');
    if (indicator) {
        indicator.textContent = strength.level;
        indicator.className = `form-text strength-${strength.score}`;
    }
}

/**
 * Copiar al portapapeles
 */
async function copyToClipboard(text, buttonElement) {
    try {
        await navigator.clipboard.writeText(text);

        if (buttonElement) {
            const originalContent = buttonElement.innerHTML;
            buttonElement.innerHTML = '<i class="bi bi-check"></i> Copiado';
            buttonElement.classList.add('btn-success');
            buttonElement.classList.remove('btn-outline-secondary');

            setTimeout(() => {
                buttonElement.innerHTML = originalContent;
                buttonElement.classList.remove('btn-success');
                buttonElement.classList.add('btn-outline-secondary');
            }, 2000);
        }
    } catch (err) {
        console.error('Error al copiar:', err);
    }
}

/**
 * Formatear tiempo restante
 */
function formatTimeRemaining(seconds) {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;

    if (minutes > 0) {
        return `${minutes}m ${remainingSeconds}s`;
    } else {
        return `${remainingSeconds}s`;
    }
}

/**
 * Debounce function para optimizar eventos
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Throttle function para limitar ejecuciones
 */
function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

/**
 * Detectar si el navegador soporta características modernas
 */
function detectBrowserFeatures() {
    return {
        localStorage: typeof Storage !== 'undefined',
        sessionStorage: typeof Storage !== 'undefined',
        webGL: !!window.WebGLRenderingContext,
        webWorkers: typeof Worker !== 'undefined',
        geolocation: 'geolocation' in navigator,
        touchEvents: 'ontouchstart' in window
    };
}

/**
 * Obtener información del navegador
 */
function getBrowserInfo() {
    const ua = navigator.userAgent;
    let browserName = 'Unknown';
    let browserVersion = 'Unknown';

    if (ua.indexOf('Firefox') > -1) {
        browserName = 'Firefox';
        browserVersion = ua.match(/Firefox\/(\d+)/)[1];
    } else if (ua.indexOf('Chrome') > -1) {
        browserName = 'Chrome';
        browserVersion = ua.match(/Chrome\/(\d+)/)[1];
    } else if (ua.indexOf('Safari') > -1) {
        browserName = 'Safari';
        browserVersion = ua.match(/Version\/(\d+)/)[1];
    } else if (ua.indexOf('Edge') > -1) {
        browserName = 'Edge';
        browserVersion = ua.match(/Edge\/(\d+)/)[1];
    }

    return {
        name: browserName,
        version: browserVersion,
        userAgent: ua,
        platform: navigator.platform,
        language: navigator.language,
        screenResolution: `${window.screen.width}x${window.screen.height}`
    };
}

/**
 * Manejar errores de JavaScript
 */
function handleErrors() {
    window.addEventListener('error', function(e) {
        console.error('JavaScript Error:', e.message);

        // Enviar error al servidor si está configurado
        if (window.AUTHO_CORE_CONFIG && window.AUTHO_CORE_CONFIG.logErrors) {
            fetch('/api/log-error/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    message: e.message,
                    filename: e.filename,
                    lineno: e.lineno,
                    colno: e.colno,
                    stack: e.error ? e.error.stack : null,
                    browser: getBrowserInfo()
                })
            }).catch(err => console.error('Error logging failed:', err));
        }
    });

    window.addEventListener('unhandledrejection', function(e) {
        console.error('Unhandled Promise Rejection:', e.reason);
    });
}

// Iniciar manejo de errores
handleErrors();

// Exportar funciones para uso global
window.AuthoCore = {
    validatePasswordStrength,
    showPasswordStrength,
    copyToClipboard,
    formatTimeRemaining,
    generateDeviceFingerprint,
    getBrowserInfo,
    detectBrowserFeatures,
    debounce,
    throttle
};