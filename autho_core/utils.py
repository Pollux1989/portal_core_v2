"""
Funciones de utilidad para autenticación y seguridad

Este módulo contiene funciones auxiliares para autenticación,
gestión de seguridad, criptografía y operaciones relacionadas.
"""

import hashlib
import secrets
import time
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator

from .models import FailedLoginAttempt, SecurityLog, UserProfile

User = get_user_model()


# Configuración de bloqueo por defecto
DEFAULT_MAX_ATTEMPTS = getattr(settings, 'AUTHO_CORE_MAX_ATTEMPTS', 5)
DEFAULT_LOCKOUT_TIME = getattr(settings, 'AUTHO_CORE_LOCKOUT_TIME', 15)  # minutos
DEFAULT_IP_RATE_LIMIT = getattr(settings, 'AUTHO_CORE_IP_RATE_LIMIT', 20)  # por hora


def check_lockout(username, ip_address=None):
    """
    Verificar si un usuario o IP están bloqueados por demasiados intentos fallidos.

    Args:
        username: Nombre de usuario a verificar
        ip_address: Dirección IP a verificar (opcional)

    Returns:
        tuple: (is_locked, remaining_time_seconds)
    """
    user_attempts = FailedLoginAttempt.get_recent_attempts(username)
    user_blocked = len(user_attempts) >= DEFAULT_MAX_ATTEMPTS

    ip_blocked = False
    if ip_address:
        ip_attempts = FailedLoginAttempt.get_ip_attempts(ip_address)
        ip_blocked = len(ip_attempts) >= DEFAULT_IP_RATE_LIMIT

    # Calcular tiempo restante de bloqueo
    remaining_time = 0
    if user_blocked or ip_blocked:
        latest_attempt = max(user_attempts, key=lambda x: x.attempt_time)
        elapsed = (timezone.now() - latest_attempt.attempt_time).total_seconds()
        lockout_duration = DEFAULT_LOCKOUT_TIME * 60  # convertir a segundos
        remaining_time = max(0, lockout_duration - elapsed)

    is_locked = (remaining_time > 0) or user_blocked or ip_blocked
    return (is_locked, remaining_time)


def record_failed_attempt(username, ip_address, user_agent=None, reason='Invalid credentials'):
    """
    Registrar un intento fallido de login.

    Args:
        username: Nombre de usuario
        ip_address: Dirección IP del cliente
        user_agent: User Agent del navegador (opcional)
        reason: Motivo del fallo
    """
    # Generar fingerprint del dispositivo
    device_fingerprint = generate_device_fingerprint(user_agent)

    FailedLoginAttempt.objects.create(
        username=username,
        ip_address=ip_address,
        user_agent=user_agent,
        success=False,
        failure_reason=reason,
        device_fingerprint=device_fingerprint
    )


def clear_failed_attempts(username, ip_address=None):
    """
    Limpiar intentos fallidos para un usuario o IP.

    Args:
        username: Nombre de usuario
        ip_address: Dirección IP (opcional)
    """
    if ip_address:
        FailedLoginAttempt.objects.filter(
            username__iexact=username,
            ip_address=ip_address
        ).delete()
    else:
        FailedLoginAttempt.objects.filter(
            username__iexact=username
        ).delete()


def is_account_locked(username):
    """
    Verificar si una cuenta está bloqueada en el perfil de usuario.

    Args:
        username: Nombre de usuario a verificar

    Returns:
        bool: True si la cuenta está bloqueada
    """
    try:
        user = User.objects.get(username__iexact=username)
        if hasattr(user, 'profile'):
            return user.profile.is_locked()
    except User.DoesNotExist:
        pass
    return False


def generate_device_fingerprint(user_agent=None):
    """
    Generar una huella única para el dispositivo.

    Args:
        user_agent: User Agent del navegador

    Returns:
        str: Hash del fingerprint
    """
    if not user_agent:
        return secrets.token_hex(16)

    # Hash del user agent + timestamp para mayor unicidad
    fingerprint = f"{user_agent}-{int(time.time())}"
    return hashlib.sha256(fingerprint.encode()).hexdigest()[:32]


def generate_mfa_secret():
    """
    Generar un secreto para autenticación de dos factores.

    Returns:
        str: Secreto de 32 caracteres en base32
    """
    return secrets.token_hex(16)  # 32 caracteres hexadecimales


def verify_mfa_code(secret, code):
    """
    Verificar un código de autenticación de dos factores.

    Args:
        secret: Secreto del usuario
        code: Código de 6 dígitos

    Returns:
        bool: True si el código es válido
    """
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)  # permitir ventana de 1 paso
    except ImportError:
        # Si pyotp no está instalado, usar validación básica
        return len(code) == 6 and code.isdigit()
    except Exception:
        return False


def get_mfa_qr_code(secret, email, issuer_name='Autho Core'):
    """
    Generar el código QR para configuración de 2FA.

    Args:
        secret: Secreto del usuario
        email: Correo electrónico del usuario
        issuer_name: Nombre de la aplicación

    Returns:
        str: URL de provisioning para Google Authenticator
    """
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=email, issuer_name=issuer_name)
    except ImportError:
        return f"otpauth://totp/{email}?secret={secret}&issuer={issuer_name}"


def log_security_event(user, event_type, request=None, description=None, metadata=None):
    """
    Registrar un evento de seguridad en el log.

    Args:
        user: Usuario relacionado (puede ser None)
        event_type: Tipo de evento
        request: Objeto de solicitud HTTP
        description: Descripción del evento
        metadata: Diccionario con metadatos adicionales

    Returns:
        SecurityLog: Objeto de log creado
    """
    ip_address = None
    user_agent = None

    if request:
        # Obtener IP real
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0].strip()
        else:
            ip_address = request.META.get('REMOTE_ADDR')

        user_agent = request.META.get('HTTP_USER_AGENT', '')

    return SecurityLog.objects.create(
        user=user,
        event_type=event_type,
        description=description or f'{event_type} event',
        ip_address=ip_address,
        user_agent=user_agent,
        metadata=metadata or {}
    )


def send_verification_email(user, request):
    """
    Enviar correo electrónico de verificación.

    Args:
        user: Usuario a verificar
        request: Objeto de solicitud HTTP

    Returns:
        bool: True si se envió correctamente
    """
    try:
        # Generar token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Construir URL de verificación
        protocol = 'https' if request.is_secure() else 'http'
        domain = request.get_host()
        verification_url = f"{protocol}://{domain}/verify-email/{uid}/{token}/"

        # Renderizar plantilla de correo
        subject = 'Verifica tu cuenta'
        message = render_to_string('autho_core/verification_email.txt', {
            'user': user,
            'verification_url': verification_url,
            'site_name': getattr(settings, 'SITE_NAME', 'Autho Core')
        })

        # Enviar correo
        send_mail(
            subject=subject,
            message=message,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com'),
            recipient_list=[user.email],
            fail_silently=False
        )

        log_security_event(user, 'EMAIL_VERIFICATION_SENT', request)
        return True

    except Exception as e:
        log_security_event(user, 'EMAIL_VERIFICATION_FAILED', request, {'error': str(e)})
        return False


def send_password_reset_email(user, request):
    """
    Enviar correo electrónico de restablecimiento de contraseña.

    Args:
        user: Usuario que solicita el reset
        request: Objeto de solicitud HTTP

    Returns:
        bool: True si se envió correctamente
    """
    try:
        # Generar token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Construir URL de reset
        protocol = 'https' if request.is_secure() else 'http'
        domain = request.get_host()
        reset_url = f"{protocol}://{domain}/password/reset/confirm/{uid}/{token}/"

        # Renderizar plantilla de correo
        subject = 'Restablece tu contraseña'
        message = render_to_string('autho_core/password_reset_email.txt', {
            'user': user,
            'reset_url': reset_url,
            'site_name': getattr(settings, 'SITE_NAME', 'Autho Core')
        })

        # Enviar correo
        send_mail(
            subject=subject,
            message=message,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com'),
            recipient_list=[user.email],
            fail_silently=False
        )

        log_security_event(user, 'PASSWORD_RESET_EMAIL_SENT', request)
        return True

    except Exception as e:
        log_security_event(user, 'PASSWORD_RESET_EMAIL_FAILED', request, {'error': str(e)})
        return False


def rate_limit_check(request, key_prefix='', max_attempts=60, period_seconds=3600):
    """
    Verificar límite de tasa para solicitudes.

    Args:
        request: Objeto de solicitud HTTP
        key_prefix: Prefijo para la clave de caché
        max_attempts: Número máximo de intentos permitidos
        period_seconds: Período de tiempo en segundos

    Returns:
        tuple: (allowed, remaining_attempts, reset_time)
    """
    # Obtener IP del cliente
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip_address = x_forwarded_for.split(',')[0].strip()
    else:
        ip_address = request.META.get('REMOTE_ADDR', '127.0.0.1')

    # Crear clave de caché
    cache_key = f"{key_prefix}_rate_limit_{ip_address}"

    # Obtener contador actual
    attempts = cache.get(cache_key, 0)
    allowed = attempts < max_attempts

    # Calcular tiempo de reset
    ttl = cache.ttl(cache_key) if hasattr(cache, 'ttl') else 0
    reset_time = int(time.time()) + ttl if ttl > 0 else 0

    # Incrementar contador si está permitido
    if allowed:
        attempts += 1
        cache.set(cache_key, attempts, period_seconds)

    remaining_attempts = max(0, max_attempts - attempts)

    return (allowed, remaining_attempts, reset_time)


def get_client_ip(request):
    """
    Obtener la dirección IP real del cliente.

    Args:
        request: Objeto de solicitud HTTP

    Returns:
        str: Dirección IP del cliente
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip


def get_user_agent(request):
    """
    Obtener el user agent del cliente.

    Args:
        request: Objeto de solicitud HTTP

    Returns:
        str: User agent del cliente
    """
    return request.META.get('HTTP_USER_AGENT', '')


def sanitize_input(text, max_length=255):
    """
    Sanitizar texto de entrada para prevenir inyecciones.

    Args:
        text: Texto a sanitizar
        max_length: Longitud máxima permitida

    Returns:
        str: Texto sanitizado
    """
    if not text:
        return ''

    # Limitar longitud
    text = text[:max_length]

    # Eliminar caracteres potencialmente peligrosos
    dangerous_chars = ['<', '>', '"', "'", '&', ';', '|', '`']
    for char in dangerous_chars:
        text = text.replace(char, '')

    return text.strip()


def validate_password_strength(password):
    """
    Validar la fortaleza de una contraseña.

    Args:
        password: Contraseña a validar

    Returns:
        tuple: (is_strong, messages)
    """
    messages = []
    is_strong = True

    if len(password) < 8:
        messages.append('La contraseña debe tener al menos 8 caracteres.')
        is_strong = False

    if not any(c.isupper() for c in password):
        messages.append('La contraseña debe contener al menos una letra mayúscula.')
        is_strong = False

    if not any(c.islower() for c in password):
        messages.append('La contraseña debe contener al menos una letra minúscula.')
        is_strong = False

    if not any(c.isdigit() for c in password):
        messages.append('La contraseña debe contener al menos un número.')
        is_strong = False

    # Validar caracteres especiales (opcional)
    # if not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
    #     messages.append('La contraseña debe contener al menos un carácter especial.')
    #     is_strong = False

    return (is_strong, messages)


def generate_secure_token(length=32):
    """
    Generar un token seguro aleatorio.

    Args:
        length: Longitud del token en bytes

    Returns:
        str: Token hexadecimal
    """
    return secrets.token_hex(length)


def hash_data(data):
    """
    Generar un hash SHA-256 de los datos.

    Args:
        data: Datos a hashear

    Returns:
        str: Hash SHA-256 hexadecimal
    """
    return hashlib.sha256(str(data).encode()).hexdigest()


def is_suspicious_activity(request, user=None):
    """
    Detectar actividad sospechosa basada en patrones.

    Args:
        request: Objeto de solicitud HTTP
        user: Usuario actual (opcional)

    Returns:
        tuple: (is_suspicious, reason)
    """
    reasons = []

    # Verificar IP de origen
    ip_address = get_client_ip(request)

    # Verificar intentos recientes desde la misma IP
    recent_attempts = FailedLoginAttempt.get_ip_attempts(ip_address, minutes=1)
    if len(recent_attempts) > 10:
        reasons.append(f'Too many attempts from IP {ip_address}')

    # Verificar user agent sospechoso
    user_agent = get_user_agent(request)
    suspicious_patterns = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget']
    if any(pattern in user_agent.lower() for pattern in suspicious_patterns):
        reasons.append(f'Suspicious user agent: {user_agent[:50]}')

    # Verificar patrones de solicitud sospechosos
    if request.method == 'POST':
        # Verificar si hay demasiados campos POST (posible ataque de inyección)
        post_fields = len(request.POST.keys())
        if post_fields > 100:
            reasons.append(f'Too many POST fields: {post_fields}')

    # Verificar si el usuario viene de una ubicación geográfica inusual
    # (requeriría integración con servicios de geolocalización)

    is_suspicious = len(reasons) > 0
    reason = '; '.join(reasons) if reasons else None

    return (is_suspicious, reason)