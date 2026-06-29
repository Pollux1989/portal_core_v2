# Autho Core

🔐 Sistema completo de autenticación y seguridad para Django - Un paquete independiente y portable listo para integrar en cualquier proyecto.

## ✨ Características

### Autenticación Completa
- ✅ **Login y Logout** seguros con protección contra ataques
- ✅ **Registro de usuarios** con validaciones de seguridad
- ✅ **Recuperación de contraseña** por correo electrónico
- ✅ **Cambio de contraseña** con validaciones de fortaleza
- ✅ **Verificación de correo electrónico** obligatoria
- ✅ **Gestión de perfil de usuario**

### Seguridad Avanzada
- 🔒 **Autenticación de Dos Factores (2FA)** compatible con Google Authenticator
- 🛡️ **Protección contra fuerza bruta** con bloqueo por intentos
- 📊 **Registro exhaustivo de eventos de seguridad** para auditoría
- 🚨 **Detección de actividad sospechosa**
- 🔑 **Códigos de respaldo** para 2FA
- 📍 **Gestión de sesiones** con información de IP y User Agent

### Funcionalidades de Seguridad
- ⏱️ **Rate limiting** configurable para solicitudes
- 🚫 **Bloqueo de IPs** maliciosas
- 🔐 **Headers de seguridad** automáticos (CSP, HSTS, X-Frame-Options, etc.)
- 👁️ **Monitoreo de sesiones** concurrentes
- 🌍 **Soporte multiidioma** (español, inglés)
- 📱 **Diseño responsive** para dispositivos móviles

### Administración
- 🎛️ **Panel de administración** extendido para usuarios
- 📈 **Dashboard de seguridad** con estadísticas
- 🔍 **Búsqueda y filtros** avanzados
- 📊 **Exportación de logs** a CSV
- 🛠️ **Acciones masivas** para gestión de usuarios

## 📋 Requisitos

- Python 3.8+
- Django 4.2+
- pyotp>=2.9.0 (para 2FA)
- qrcode>=7.4.0 (para códigos QR)
- Pillow>=10.0.0 (para imágenes)

## 🚀 Instalación

### Instalación via pip

```bash
pip install autho-core
```

### Instalación desde código fuente

```bash
# Clonar el repositorio
git clone https://github.com/authocore/autho-core.git
cd autho-core

# Instalar en modo desarrollo
pip install -e .
```

### Instalación con dependencias opcionales

```bash
# Con herramientas de desarrollo
pip install autho-core[dev]

# Con herramientas de testing
pip install autho-core[testing]

# Con herramientas de seguridad
pip install autho-core[security]

# Con documentación
pip install autho-core[docs]

# Todas las dependencias
pip install autho-core[dev,testing,security,docs]
```

## ⚙️ Configuración

### 1. Agregar a INSTALLED_APPS

```python
# settings.py
INSTALLED_APPS = [
    # ... otras apps
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'autho_core',  # ← Agregar esta línea
]
```

### 2. Configurar URLs

```python
# urls.py principal
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('autho_core.urls')),  # ← Agregar esta línea
    # ... otras URLs
]
```

### 3. Configurar Middleware (opcional pero recomendado)

```python
# settings.py
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',

    # Middleware de Autho Core
    'autho_core.middleware.SecurityHeadersMiddleware',
    'autho_core.middleware.RateLimitMiddleware',
    'autho_core.middleware.SecurityCheckMiddleware',
    'autho_core.middleware.SessionSecurityMiddleware',
    'autho_core.middleware.LoginAttemptMiddleware',
    'autho_core.middleware.AccountLockoutMiddleware',
    'autho_core.middleware.PasswordExpiryMiddleware',
]
```

### 4. Configurar settings (opcional)

```python
# settings.py
import os

# Configuración de correo (requerida para verificación y recuperación)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'tu-correo@gmail.com'
EMAIL_HOST_PASSWORD = 'tu-password'
DEFAULT_FROM_EMAIL = 'noreply@tudominio.com'

# Configuración de Autho Core
AUTHO_CORE_MAX_ATTEMPTS = 5  # Máximo de intentos fallidos antes de bloqueo
AUTHO_CORE_LOCKOUT_TIME = 15  # Tiempo de bloqueo en minutos
AUTHO_CORE_IP_RATE_LIMIT = 20  # Solicitudes por hora por IP
AUTHO_CORE_PASSWORD_EXPIRY_DAYS = 90  # Expiración de contraseña en días
AUTHO_CORE_MAX_CONCURRENT_SESSIONS = 3  # Máximo de sesiones simultáneas
AUTHO_CORE_SESSION_CHECK_IP = True  # Verificar IP en sesiones
AUTHO_CORE_SESSION_CHECK_USER_AGENT = True  # Verificar User Agent en sesiones

# Headers de seguridad
SECURE_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_SECURITY_POLICY = "default-src 'self'"
SECURE_HSTS_SECONDS = 31536000
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Configuración del sitio
SITE_NAME = 'Tu Aplicación'
SITE_URL = 'https://tudominio.com'
```

### 5. Ejecutar migraciones

```bash
python manage.py makemigrations
python manage.py migrate
```

### 6. Recopilar archivos estáticos

```bash
python manage.py collectstatic
```

## 📖 Uso

### URLs Disponibles

- `/auth/login/` - Inicio de sesión
- `/auth/logout/` - Cierre de sesión
- `/auth/register/` - Registro de usuarios
- `/auth/register/success/` - Registro exitoso
- `/auth/password/change/` - Cambio de contraseña
- `/auth/password/change/done/` - Contraseña cambiada
- `/auth/password/reset/` - Recuperación de contraseña
- `/auth/password/reset/done/` - Correo enviado
- `/auth/password/reset/confirm/<uidb64>/<token>/` - Confirmar recuperación
- `/auth/password/reset/complete/` - Recuperación completada
- `/auth/profile/` - Perfil de usuario
- `/auth/profile/edit/` - Editar perfil
- `/auth/lockout/` - Página de bloqueo
- `/auth/verify-email/<uidb64>/<token>/` - Verificar correo
- `/auth/mfa/setup/` - Configurar 2FA
- `/auth/mfa/verify/` - Verificar 2FA
- `/auth/mfa/disable/` - Deshabilitar 2FA

### Ejemplos de Uso

#### Usar decoradores de seguridad

```python
from autho_core.decorators import (
    login_required, rate_limit, require_2fa,
    verified_email_required, security_check
)

# Requerir login con rate limiting
@rate_limit(max_attempts=10, period_seconds=60)
@login_required
def mi_vista_protegida(request):
    return render(request, 'mi_template.html')

# Requerir 2FA
@require_2fa
@login_required
def vista_confidencial(request):
    return render(request, 'confidencial.html')

# Requerir correo verificado
@verified_email_required
@login_required
def vista_verificada(request):
    return render(request, 'verificado.html')

# Verificación de seguridad
@security_check
@login_required
def vista_segura(request):
    return render(request, 'seguro.html')
```

#### Usar funciones de utilidad

```python
from autho_core.utils import (
    log_security_event, send_verification_email,
    check_lockout, validate_password_strength
)

# Registrar evento de seguridad
log_security_event(
    user=request.user,
    event_type='CUSTOM_EVENT',
    request=request,
    description='Evento personalizado'
)

# Enviar correo de verificación
send_verification_email(user, request)

# Verificar si una cuenta está bloqueada
is_locked, remaining_time = check_lockout(username)

# Validar fortaleza de contraseña
is_strong, messages = validate_password_strength(password)
```

## 🎨 Personalización

### Personalizar Templates

Autho Core usa templates base que pueden ser sobrescritos en tu proyecto:

1. Crea el directorio `templates/autho_core/` en tu proyecto
2. Copia los templates que quieras personalizar desde `autho_core/templates/autho_core/`
3. Modifica según tus necesidades

```bash
mkdir -p templates/autho_core
cp -r venv/lib/pythonX.X/site-packages/autho_core/templates/autho_core/*.html templates/autho_core/
```

### Personalizar Estilos

Los estilos CSS pueden ser sobrescritos creando tu propio archivo:

```css
/* En tu static/css/custom.css */
.auth-card {
    max-width: 600px; /* Personalizar ancho */
    background: your-color; /* Personalizar fondo */
}
```

## 🧪 Testing

```bash
# Ejecutar tests
pytest

# Ejecutar tests con coverage
pytest --cov=autho_core --cov-report=html

# Ejecutar tests específicos
pytest tests/test_views.py
```

## 📊 Panel de Administración

Autho Core extiende el panel de administración de Django con:

- **Dashboard de Seguridad**: Vista general de estadísticas
- **Gestión de Perfiles**: Información extendida de usuarios
- **Logs de Seguridad**: Registro detallado de eventos
- **Intentos Fallidos**: Historial de intentos de login
- **Sesiones Activas**: Gestión de sesiones de usuarios
- **Códigos de Respaldo**: Gestión de códigos 2FA

## 🔒 Configuración de Seguridad Avanzada

### Headers HTTP Personalizados

```python
# settings.py
SECURE_FRAME_OPTIONS = 'SAMEORIGIN'  # Cambiar valor
SECURE_CONTENT_SECURITY_POLICY = """
    default-src 'self';
    script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net;
    style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;
    img-src 'self' data: https:;
"""
SECURE_HSTS_SECONDS = 63072000  # 2 años
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

## 🌍 Multiidioma

Autho Core soporta múltiples idiomas. Los archivos de traducción están en `autho_core/locale/`.

```python
# settings.py
LANGUAGE_CODE = 'es'
USE_I18N = True
USE_L10N = True
USE_TZ = True
```

## 📝 Licencia

Este proyecto está licenciado bajo la Licencia MIT.

## 🙋 Soporte

Para soporte y contribuciones, por favor visita nuestro repositorio en GitHub.

---

**Autor**: Autho Core Team
**Versión**: 1.0.0

¡Gracias por usar Autho Core! 🎉