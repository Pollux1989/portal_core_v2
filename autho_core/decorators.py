"""
Decoradores de seguridad para Autho Core

Este módulo contiene decoradores personalizados para implementar
restricciones de seguridad en vistas y funciones.
"""

from functools import wraps
from django.http import JsonResponse, HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.conf import settings
from django.shortcuts import redirect
from django.contrib import messages

from .utils import (
    rate_limit_check, get_client_ip, is_suspicious_activity,
    log_security_event, is_account_locked, check_lockout
)


def rate_limit(max_attempts=60, period_seconds=3600, key_prefix=''):
    """
    Decorador para limitar la tasa de solicitudes.

    Args:
        max_attempts: Número máximo de intentos permitidos
        period_seconds: Período de tiempo en segundos
        key_prefix: Prefijo para la clave de caché

    Usage:
        @rate_limit(max_attempts=10, period_seconds=60, key_prefix='api')
        def my_view(request):
            return JsonResponse({'status': 'ok'})
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Verificar límite de tasa
            allowed, remaining, reset_time = rate_limit_check(
                request,
                key_prefix=key_prefix,
                max_attempts=max_attempts,
                period_seconds=period_seconds
            )

            if not allowed:
                # Si se excede el límite, responder con 429
                log_security_event(
                    request.user if request.user.is_authenticated else None,
                    'RATE_LIMIT_EXCEEDED',
                    request,
                    {'key_prefix': key_prefix, 'max_attempts': max_attempts}
                )

                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({
                        'error': 'Too many requests',
                        'message': f'Rate limit exceeded. Try again after {reset_time} seconds.',
                        'retry_after': reset_time
                    }, status=429)
                else:
                    messages.error(
                        request,
                        f'Too many requests. Please try again after {reset_time} seconds.'
                    )
                    return redirect('autho_core:login')

            # Agregar información de límite de tasa a la respuesta
            response = view_func(request, *args, **kwargs)

            if hasattr(response, '__setitem__'):
                response['X-RateLimit-Limit'] = str(max_attempts)
                response['X-RateLimit-Remaining'] = str(remaining)
                response['X-RateLimit-Reset'] = str(reset_time)

            return response

        return _wrapped_view

    return decorator


def require_2fa(view_func=None, redirect_url='autho_core:mfa_verify'):
    """
    Decorador para requerir autenticación de dos factores.

    Usage:
        @require_2fa
        def my_view(request):
            return JsonResponse({'status': 'ok'})

        O con URL personalizada:
        @require_2fa(redirect_url='my_custom_mfa_view')
        def my_view(request):
            return JsonResponse({'status': 'ok'})
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            # Verificar si el usuario tiene 2FA habilitado
            if hasattr(request.user, 'profile') and request.user.profile:
                if request.user.profile.mfa_enabled:
                    # Verificar si ya se ha verificado 2FA en esta sesión
                    if request.session.get('mfa_verified'):
                        return view_func(request, *args, **kwargs)

                    # Si no está verificado, redirigir a verificación 2FA
                    request.session['mfa_redirect_url'] = request.get_full_path()
                    return redirect(redirect_url)

            # Si no tiene 2FA habilitado, continuar normalmente
            return view_func(request, *args, **kwargs)

        return _wrapped_view

    if view_func is not None:
        return decorator(view_func)
    return decorator


def verified_email_required(view_func=None, redirect_url='autho_core:login'):
    """
    Decorador para requerir correo electrónico verificado.

    Usage:
        @verified_email_required
        def my_view(request):
            return JsonResponse({'status': 'ok'})
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            # Verificar si el correo está verificado
            if hasattr(request.user, 'profile') and request.user.profile:
                if not request.user.profile.email_verified:
                    messages.warning(
                        request,
                        'Please verify your email address to continue.'
                    )
                    return redirect(redirect_url)

            # Si no tiene perfil o el correo está verificado, continuar
            return view_func(request, *args, **kwargs)

        return _wrapped_view

    if view_func is not None:
        return decorator(view_func)
    return decorator


def account_not_locked(view_func=None):
    """
    Decorador para verificar que la cuenta no esté bloqueada.

    Usage:
        @account_not_locked
        def my_view(request):
            return JsonResponse({'status': 'ok'})
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            # Verificar si la cuenta está bloqueada
            if hasattr(request.user, 'profile') and request.user.profile:
                if request.user.profile.is_locked():
                    messages.error(
                        request,
                        'Your account has been locked. Please contact support.'
                    )
                    return redirect('autho_core:login')

            # Si no está bloqueada, continuar
            return view_func(request, *args, **kwargs)

        return _wrapped_view

    if view_func is not None:
        return decorator(view_func)
    return decorator


def security_check(view_func=None):
    """
    Decorador para realizar verificaciones de seguridad adicionales.

    Detecta actividad sospechosa y puede bloquear solicitudes.

    Usage:
        @security_check
        def my_view(request):
            return JsonResponse({'status': 'ok'})
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
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

                # Opcional: bloquear la solicitud
                if getattr(settings, 'AUTHO_CORE_BLOCK_SUSPICIOUS', False):
                    if request.headers.get('Accept') == 'application/json':
                        return JsonResponse({
                            'error': 'Security check failed',
                            'message': 'Your request was flagged as suspicious.'
                        }, status=403)
                    else:
                        messages.error(
                            request,
                            'Security check failed. Your request was flagged as suspicious.'
                        )
                        return redirect('autho_core:login')

            # Si no hay actividad sospechosa, continuar
            return view_func(request, *args, **kwargs)

        return _wrapped_view

    if view_func is not None:
        return decorator(view_func)
    return decorator


def staff_member_required_custom(view_func=None, redirect_url='autho_core:login'):
    """
    Decorador para requerir que el usuario sea miembro del staff.

    Similar a Django's @staff_member_required pero con redirección personalizada.

    Usage:
        @staff_member_required_custom
        def my_view(request):
            return JsonResponse({'status': 'ok'})
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                messages.warning(request, 'Please log in to access this page.')
                return redirect(redirect_url)

            if not request.user.is_staff:
                messages.error(request, 'You do not have permission to access this page.')
                return redirect('autho_core:profile')

            return view_func(request, *args, **kwargs)

        return _wrapped_view

    if view_func is not None:
        return decorator(view_func)
    return decorator


def superuser_required(view_func=None, redirect_url='autho_core:login'):
    """
    Decorador para requerir que el usuario sea superusuario.

    Usage:
        @superuser_required
        def my_view(request):
            return JsonResponse({'status': 'ok'})
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                messages.warning(request, 'Please log in to access this page.')
                return redirect(redirect_url)

            if not request.user.is_superuser:
                messages.error(request, 'You do not have permission to access this page.')
                return redirect('autho_core:profile')

            return view_func(request, *args, **kwargs)

        return _wrapped_view

    if view_func is not None:
        return decorator(view_func)
    return decorator


def csrf_exempt_custom(view_func=None):
    """
    Decorador personalizado para eximir de CSRF (uso con precaución).

    Usage:
        @csrf_exempt_custom
        def my_view(request):
            return JsonResponse({'status': 'ok'})
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Agregar header de seguridad personalizado
            response = view_func(request, *args, **kwargs)

            if hasattr(response, '__setitem__'):
                response['X-CSRF-Protection'] = 'Custom-Exempt'

            return response

        return _wrapped_view

    if view_func is not None:
        return decorator(view_func)
    return decorator


def ssl_required(view_func=None):
    """
    Decorador para requerir SSL/HTTPS.

    Usage:
        @ssl_required
        def my_view(request):
            return JsonResponse({'status': 'ok'})
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.is_secure():
                # Si no es HTTPS, redirigir a HTTPS
                if getattr(settings, 'DEBUG', False):
                    # En modo de desarrollo, permitir HTTP
                    return view_func(request, *args, **kwargs)

                ssl_url = request.build_absolute_uri(request.get_full_path()).replace('http://', 'https://')
                return redirect(ssl_url)

            return view_func(request, *args, **kwargs)

        return _wrapped_view

    if view_func is not None:
        return decorator(view_func)
    return decorator


def conditional_login_required(view_func=None, condition=lambda request: True):
    """
    Decorador para requerir login condicionalmente.

    Usage:
        @conditional_login_required(condition=lambda request: request.GET.get('auth') == 'required')
        def my_view(request):
            return JsonResponse({'status': 'ok'})
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if condition(request):
                if not request.user.is_authenticated:
                    messages.warning(request, 'Please log in to access this page.')
                    return redirect('autho_core:login')

            return view_func(request, *args, **kwargs)

        return _wrapped_view

    if view_func is not None:
        return decorator(view_func)
    return decorator


def ip_whitelist(allowed_ips=None):
    """
    Decorador para permitir solo ciertas direcciones IP.

    Usage:
        @ip_whitelist(allowed_ips=['192.168.1.1', '10.0.0.1'])
        def my_view(request):
            return JsonResponse({'status': 'ok'})
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            ip_address = get_client_ip(request)

            if allowed_ips and ip_address not in allowed_ips:
                log_security_event(
                    request.user if request.user.is_authenticated else None,
                    'IP_NOT_ALLOWED',
                    request,
                    {'ip_address': ip_address}
                )

                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({
                        'error': 'Access denied',
                        'message': 'Your IP address is not allowed to access this resource.'
                    }, status=403)
                else:
                    return HttpResponseForbidden(
                        'Your IP address is not allowed to access this resource.'
                    )

            return view_func(request, *args, **kwargs)

        return _wrapped_view

    return decorator


def ip_blacklist(blocked_ips=None):
    """
    Decorador para bloquear ciertas direcciones IP.

    Usage:
        @ip_blacklist(blocked_ips=['192.168.1.100', '10.0.0.100'])
        def my_view(request):
            return JsonResponse({'status': 'ok'})
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            ip_address = get_client_ip(request)

            if blocked_ips and ip_address in blocked_ips:
                log_security_event(
                    request.user if request.user.is_authenticated else None,
                    'IP_BLOCKED',
                    request,
                    {'ip_address': ip_address}
                )

                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({
                        'error': 'Access denied',
                        'message': 'Your IP address has been blocked.'
                    }, status=403)
                else:
                    return HttpResponseForbidden(
                        'Your IP address has been blocked.'
                    )

            return view_func(request, *args, **kwargs)

        return _wrapped_view

    return decorator


def password_change_required(view_func=None, grace_period_seconds=0):
    """
    Decorador para requerir cambio de contraseña después de cierto tiempo.

    Usage:
        @password_change_required(grace_period_seconds=30*24*60*60)  # 30 días
        def my_view(request):
            return JsonResponse({'status': 'ok'})
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            # Verificar si se requiere cambio de contraseña
            if hasattr(request.user, 'profile') and request.user.profile:
                if request.user.profile.require_password_change:
                    messages.warning(
                        request,
                        'You must change your password before continuing.'
                    )
                    return redirect('autho_core:password_change')

                # Verificar antigüedad de la contraseña
                if grace_period_seconds > 0 and request.user.profile.password_changed_at:
                    from django.utils import timezone
                    time_since_change = (timezone.now() - request.user.profile.password_changed_at).total_seconds()

                    if time_since_change > grace_period_seconds:
                        # Marcar que se requiere cambio de contraseña
                        request.user.profile.require_password_change = True
                        request.user.profile.save()

                        messages.warning(
                            request,
                            'Your password has expired. Please change it before continuing.'
                        )
                        return redirect('autho_core:password_change')

            return view_func(request, *args, **kwargs)

        return _wrapped_view

    if view_func is not None:
        return decorator(view_func)
    return decorator