"""
Middleware de seguridad para Autho Core

Este módulo contiene middleware personalizado para implementar
capas adicionales de seguridad en la aplicación Django.
"""

from django.http import JsonResponse, HttpResponseForbidden
from django.conf import settings
from django.utils import timezone
from django.contrib.auth import logout
from django.core.cache import cache
from django.shortcuts import redirect
from django.contrib import messages

from .utils import (
    get_client_ip, get_user_agent, is_suspicious_activity,
    log_security_event, check_lockout, generate_device_fingerprint
)
from .models import SecurityLog, UserProfile, SessionManagement


class SecurityHeadersMiddleware:
    """
    Middleware para agregar headers de seguridad HTTP.

    Agrega headers como X-Frame-Options, X-Content-Type-Options,
    X-XSS-Protection, Content-Security-Policy, etc.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Headers de seguridad estándar
        response['X-Frame-Options'] = getattr(settings, 'SECURE_FRAME_OPTIONS', 'DENY')
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-XSS-Protection'] = '1; mode=block'

        # Content Security Policy (si está configurado)
        csp = getattr(settings, 'SECURE_CONTENT_SECURITY_POLICY', None)
        if csp:
            response['Content-Security-Policy'] = csp

        # Strict-Transport-Security (solo en HTTPS)
        if request.is_secure():
            hsts_max_age = getattr(settings, 'SECURE_HSTS_SECONDS', 31536000)
            response['Strict-Transport-Security'] = f'max-age={hsts_max_age}; includeSubDomains'

        # Referrer Policy
        response['Referrer-Policy'] = getattr(settings, 'SECURE_REFERRER_POLICY', 'strict-origin-when-cross-origin')

        # Permissions Policy (anteriormente Feature-Policy)
        permissions_policy = getattr(settings, 'SECURE_PERMISSIONS_POLICY', None)
        if permissions_policy:
            response['Permissions-Policy'] = permissions_policy

        return response


class RateLimitMiddleware:
    """
    Middleware para limitar la tasa de solicitudes global.

    Protege contra ataques de fuerza bruta y DDoS a nivel de aplicación.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.max_requests = getattr(settings, 'AUTHO_CORE_RATE_LIMIT_MAX_REQUESTS', 1000)
        self.period_seconds = getattr(settings, 'AUTHO_CORE_RATE_LIMIT_PERIOD', 3600)

    def __call__(self, request):
        # Obtener IP del cliente
        ip_address = get_client_ip(request)

        # Crear clave de caché
        cache_key = f"rate_limit_global_{ip_address}"

        # Obtener contador actual
        request_count = cache.get(cache_key, 0)

        # Verificar si se excede el límite
        if request_count >= self.max_requests:
            log_security_event(
                request.user if request.user.is_authenticated else None,
                'GLOBAL_RATE_LIMIT_EXCEEDED',
                request,
                {'ip_address': ip_address, 'request_count': request_count}
            )

            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({
                    'error': 'Too many requests',
                    'message': 'Global rate limit exceeded. Please try again later.'
                }, status=429)
            else:
                return HttpResponseForbidden('Too many requests. Please try again later.')

        # Incrementar contador
        cache.set(cache_key, request_count + 1, self.period_seconds)

        # Agregar headers de rate limit
        response = self.get_response(request)
        response['X-RateLimit-Limit'] = str(self.max_requests)
        response['X-RateLimit-Remaining'] = str(self.max_requests - request_count - 1)

        return response


class SecurityCheckMiddleware:
    """
    Middleware para realizar verificaciones de seguridad en cada solicitud.

    Detecta actividad sospechosa, patrones de ataque y puede bloquear solicitudes.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.block_suspicious = getattr(settings, 'AUTHO_CORE_BLOCK_SUSPICIOUS', False)

    def __call__(self, request):
        # Verificar actividad sospechosa
        is_suspicious, reason = is_suspicious_activity(
            request,
            request.user if request.user.is_authenticated else None
        )

        if is_suspicious:
            log_security_event(
                request.user if request.user.is_authenticated else None,
                'SUSPICIOUS_ACTIVITY',
                request,
                {'reason': reason}
            )

            if self.block_suspicious:
                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({
                        'error': 'Security check failed',
                        'message': 'Your request was flagged as suspicious.'
                    }, status=403)
                else:
                    return HttpResponseForbidden(
                        'Security check failed. Your request was flagged as suspicious.'
                    )

        return self.get_response(request)


class SessionSecurityMiddleware:
    """
    Middleware para gestionar la seguridad de las sesiones de usuario.

    Implementa protección contra secuestro de sesión, IP fija,
    y detección de sesiones concurrentes.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.check_ip = getattr(settings, 'AUTHO_CORE_SESSION_CHECK_IP', True)
        self.check_user_agent = getattr(settings, 'AUTHO_CORE_SESSION_CHECK_USER_AGENT', True)
        self.max_concurrent_sessions = getattr(settings, 'AUTHO_CORE_MAX_CONCURRENT_SESSIONS', 3)

    def __call__(self, request):
        if not request.user.is_authenticated:
            return self.get_response(request)

        try:
            profile = request.user.profile
        except UserProfile.DoesNotExist:
            profile = UserProfile.objects.create(user=request.user)

        # Verificar IP de la sesión
        if self.check_ip and profile.current_login_ip:
            current_ip = get_client_ip(request)
            if current_ip != profile.current_login_ip:
                log_security_event(
                    request.user,
                    'SESSION_IP_MISMATCH',
                    request,
                    {'expected_ip': profile.current_login_ip, 'actual_ip': current_ip}
                )

                # Opcional: cerrar sesión si la IP cambia
                if getattr(settings, 'AUTHO_CORE_SESSION_STRICT_IP', False):
                    logout(request)
                    messages.warning(
                        request,
                        'Your session has been terminated due to IP address change.'
                    )
                    return redirect('autho_core:login')

        # Verificar User Agent de la sesión
        if self.check_user_agent and profile.current_user_agent:
            current_user_agent = get_user_agent(request)
            if current_user_agent != profile.current_user_agent:
                log_security_event(
                    request.user,
                    'SESSION_USER_AGENT_MISMATCH',
                    request,
                    {'expected': profile.current_user_agent[:50], 'actual': current_user_agent[:50]}
                )

                # Opcional: cerrar sesión si el user agent cambia
                if getattr(settings, 'AUTHO_CORE_SESSION_STRICT_USER_AGENT', False):
                    logout(request)
                    messages.warning(
                        request,
                        'Your session has been terminated due to browser change.'
                    )
                    return redirect('autho_core:login')

        # Verificar sesiones concurrentes
        if self.max_concurrent_sessions > 0:
            active_sessions = SessionManagement.objects.filter(
                user=request.user,
                is_active=True
            ).count()

            if active_sessions > self.max_concurrent_sessions:
                # Terminar la sesión más antigua
                oldest_session = SessionManagement.objects.filter(
                    user=request.user,
                    is_active=True
                ).order_by('last_activity').first()

                if oldest_session:
                    oldest_session.terminate()
                    log_security_event(
                        request.user,
                        'SESSION_TERMINATED_CONCURRENT',
                        request,
                        {'terminated_session': oldest_session.session_key}
                    )

        return self.get_response(request)


class LoginAttemptMiddleware:
    """
    Middleware para rastrear intentos de login y bloquear IPs abusivas.

    Registra todos los intentos de login y puede bloquear IPs que
    realizan demasiados intentos fallidos.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.max_attempts = getattr(settings, 'AUTHO_CORE_MAX_LOGIN_ATTEMPTS', 10)
        self.lockout_time = getattr(settings, 'AUTHO_CORE_LOGIN_LOCKOUT_TIME', 15)  # minutos

    def __call__(self, request):
        # Solo procesar solicitudes de login
        if request.path == '/login/' and request.method == 'POST':
            ip_address = get_client_ip(request)
            username = request.POST.get('username', '')

            # Verificar si la IP está bloqueada
            is_locked, remaining_time = check_lockout(username, ip_address)

            if is_locked:
                log_security_event(
                    None,
                    'LOGIN_ATTEMPT_BLOCKED',
                    request,
                    {'username': username, 'ip_address': ip_address, 'remaining_time': remaining_time}
                )

                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({
                        'error': 'Too many login attempts',
                        'message': f'Account locked. Try again in {remaining_time} seconds.'
                    }, status=429)
                else:
                    messages.error(
                        request,
                        f'Too many login attempts. Please try again in {remaining_time} seconds.'
                    )
                    return redirect('autho_core:login')

        return self.get_response(request)


class AccountLockoutMiddleware:
    """
    Middleware para verificar si las cuentas de usuario están bloqueadas.

    Verifica el estado de bloqueo de las cuentas y puede forzar
    el cierre de sesión si la cuenta está bloqueada.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            return self.get_response(request)

        try:
            profile = request.user.profile

            if profile.is_locked():
                log_security_event(
                    request.user,
                    'LOCKED_ACCOUNT_ACCESS_ATTEMPT',
                    request,
                    {'lock_reason': profile.lock_reason, 'locked_until': profile.locked_until}
                )

                # Cerrar sesión si la cuenta está bloqueada
                logout(request)
                messages.error(
                    request,
                    f'Your account has been locked. Reason: {profile.lock_reason}'
                )
                return redirect('autho_core:login')

        except UserProfile.DoesNotExist:
            pass

        return self.get_response(request)


class PasswordExpiryMiddleware:
    """
    Middleware para verificar la expiración de contraseñas.

    Fuerza a los usuarios a cambiar su contraseña después de un
    período de tiempo determinado.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.password_expiry_days = getattr(settings, 'AUTHO_CORE_PASSWORD_EXPIRY_DAYS', 90)

    def __call__(self, request):
        if not request.user.is_authenticated:
            return self.get_response(request)

        # Excluir rutas de cambio de contraseña
        if request.path in ['/password/change/', '/logout/']:
            return self.get_response(request)

        try:
            profile = request.user.profile

            if profile.require_password_change:
                messages.warning(
                    request,
                    'You must change your password before continuing.'
                )
                return redirect('autho_core:password_change')

            # Verificar antigüedad de la contraseña
            if self.password_expiry_days > 0 and profile.password_changed_at:
                days_since_change = (timezone.now() - profile.password_changed_at).days

                if days_since_change > self.password_expiry_days:
                    # Marcar que se requiere cambio de contraseña
                    profile.require_password_change = True
                    profile.save()

                    messages.warning(
                        request,
                        f'Your password has expired ({days_since_change} days old). Please change it.'
                    )
                    return redirect('autho_core:password_change')

        except UserProfile.DoesNotExist:
            pass

        return self.get_response(request)


class AuditLogMiddleware:
    """
    Middleware para registrar todas las solicitudes HTTP para auditoría.

    Guarda información sobre cada solicitud para análisis de seguridad
    y cumplimiento de requisitos de auditoría.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.log_all_requests = getattr(settings, 'AUTHO_CORE_LOG_ALL_REQUESTS', False)
        self.log_authenticated_only = getattr(settings, 'AUTHO_CORE_LOG_AUTHENTICATED_ONLY', True)

    def __call__(self, request):
        # Determinar si se debe registrar esta solicitud
        should_log = self.log_all_requests

        if self.log_authenticated_only and not should_log:
            should_log = request.user.is_authenticated

        if should_log:
            # Registrar la solicitud
            log_security_event(
                request.user if request.user.is_authenticated else None,
                'HTTP_REQUEST',
                request,
                {
                    'method': request.method,
                    'path': request.path,
                    'query_string': request.GET.urlencode(),
                    'content_type': request.content_type,
                    'content_length': request.META.get('CONTENT_LENGTH', 0)
                }
            )

        response = self.get_response(request)

        # Registrar la respuesta si es un error
        if response.status_code >= 400 and should_log:
            log_security_event(
                request.user if request.user.is_authenticated else None,
                'HTTP_ERROR_RESPONSE',
                request,
                {
                    'status_code': response.status_code,
                    'method': request.method,
                    'path': request.path
                }
            )

        return response


class DeviceFingerprintMiddleware:
    """
    Middleware para generar y verificar huellas de dispositivo.

    Crea una huella única para cada dispositivo y la utiliza para
    detectar cambios de dispositivo sospechosos.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Generar fingerprint del dispositivo
        user_agent = get_user_agent(request)
        device_fingerprint = generate_device_fingerprint(user_agent)

        # Guardar en la sesión
        request.session['device_fingerprint'] = device_fingerprint

        # Verificar si el usuario está autenticado
        if request.user.is_authenticated:
            try:
                profile = request.user.profile

                # Verificar si hay un fingerprint guardado
                if hasattr(profile, 'device_fingerprint') and profile.device_fingerprint:
                    # Verificar si el fingerprint ha cambiado
                    if profile.device_fingerprint != device_fingerprint:
                        log_security_event(
                            request.user,
                            'DEVICE_FINGERPRINT_MISMATCH',
                            request,
                            {
                                'expected': profile.device_fingerprint,
                                'actual': device_fingerprint
                            }
                        )

                        # Opcional: requerir re-autenticación
                        if getattr(settings, 'AUTHO_CORE_REQUIRE_REAUTH_ON_DEVICE_CHANGE', False):
                            request.session['require_reauth'] = True
                            messages.warning(
                                request,
                                'We detected a new device. Please re-authenticate for security.'
                            )

            except UserProfile.DoesNotExist:
                pass

        return self.get_response(request)