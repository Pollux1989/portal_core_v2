"""
Señales de seguridad para Autho Core

Este módulo contiene las señales de Django que se disparan en eventos
relacionados con la autenticación y seguridad del sistema.
"""

from django.db.models.signals import post_save, pre_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.utils import timezone

from .models import UserProfile, SecurityLog, SessionManagement
from .utils import log_security_event, get_client_ip, get_user_agent


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Señal para crear automáticamente el perfil de usuario cuando se crea un usuario.
    """
    if created:
        UserProfile.objects.create(
            user=instance,
            email_verified=False,
            mfa_enabled=False
        )


@receiver(pre_save, sender=User)
def log_user_changes(sender, instance, **kwargs):
    """
    Señal para registrar cambios importantes en los usuarios.
    """
    try:
        # Si el usuario ya existe, verificar cambios importantes
        if instance.pk:
            old_user = User.objects.get(pk=instance.pk)

            # Verificar si el correo ha cambiado
            if old_user.email != instance.email:
                # Aquí se podría enviar un correo de notificación
                pass

            # Verificar si el estado activo ha cambiado
            if old_user.is_active != instance.is_active:
                reason = 'Account activated' if instance.is_active else 'Account deactivated'
                SecurityLog.objects.create(
                    user=instance,
                    event_type='ACCOUNT_STATUS_CHANGE',
                    description=reason,
                    metadata={
                        'old_status': old_user.is_active,
                        'new_status': instance.is_active
                    }
                )

    except User.DoesNotExist:
        pass


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """
    Señal para registrar inicios de sesión exitosos.
    """
    try:
        profile = user.profile

        # Actualizar información de IP y User Agent
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)

        # Guardar la información anterior
        profile.last_login_ip = profile.current_login_ip
        profile.last_user_agent = profile.current_user_agent

        # Establecer nueva información
        profile.current_login_ip = ip_address
        profile.current_user_agent = user_agent

        profile.save()

        # Crear registro de sesión
        session_key = request.session.session_key
        device_fingerprint = request.session.get('device_fingerprint', '')

        SessionManagement.objects.update_or_create(
            session_key=session_key,
            defaults={
                'user': user,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'device_fingerprint': device_fingerprint,
                'is_current': True,
                'is_active': True
            }
        )

        # Marcar otras sesiones como no actuales
        SessionManagement.objects.filter(
            user=user,
            session_key__ne=session_key
        ).update(is_current=False)

        # Registrar evento de login
        log_security_event(user, 'LOGIN_SUCCESS', request)

    except UserProfile.DoesNotExist:
        # Crear perfil si no existe
        UserProfile.objects.create(user=user)


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    """
    Señal para registrar cierres de sesión.
    """
    if user:
        # Marcar la sesión como inactiva
        session_key = request.session.session_key
        if session_key:
            SessionManagement.objects.filter(
                session_key=session_key
            ).update(is_active=False)

        # Registrar evento de logout
        log_security_event(user, 'LOGOUT', request)


@receiver(user_login_failed)
def log_failed_login(sender, credentials, request, **kwargs):
    """
    Señal para registrar intentos fallidos de inicio de sesión.
    """
    username = credentials.get('username', 'unknown')
    ip_address = get_client_ip(request)
    user_agent = get_user_agent(request)

    # Crear registro de intento fallido
    from .models import FailedLoginAttempt
    import secrets

    FailedLoginAttempt.objects.create(
        username=username,
        ip_address=ip_address,
        user_agent=user_agent,
        success=False,
        failure_reason='Invalid credentials',
        device_fingerprint=request.session.get('device_fingerprint', secrets.token_hex(16))
    )

    # Verificar si el usuario existe para eventos de seguridad adicionales
    try:
        user = User.objects.get(username__iexact=username)
        log_security_event(user, 'LOGIN_FAILED', request, {'reason': 'Invalid credentials'})
    except User.DoesNotExist:
        # Registrar intento con usuario no existente
        log_security_event(None, 'LOGIN_FAILED_UNKNOWN_USER', request, {
            'username': username,
            'ip_address': ip_address
        })


@receiver(post_save, sender=UserProfile)
def log_profile_changes(sender, instance, created, **kwargs):
    """
    Señal para registrar cambios importantes en el perfil de usuario.
    """
    if not created:
        try:
            # Verificar si el perfil existía anteriormente
            old_profile = UserProfile.objects.get(pk=instance.pk)

            # Verificar cambios en el estado 2FA
            if old_profile.mfa_enabled != instance.mfa_enabled:
                event_type = 'MFA_ENABLED' if instance.mfa_enabled else 'MFA_DISABLED'
                SecurityLog.objects.create(
                    user=instance.user,
                    event_type=event_type,
                    description=f'2FA {"enabled" if instance.mfa_enabled else "disabled"} by user',
                    metadata={
                        'previous_state': old_profile.mfa_enabled,
                        'new_state': instance.mfa_enabled
                    }
                )

            # Verificar cambios en el estado de bloqueo
            if old_profile.account_locked != instance.account_locked:
                event_type = 'ACCOUNT_LOCKED' if instance.account_locked else 'ACCOUNT_UNLOCKED'
                SecurityLog.objects.create(
                    user=instance.user,
                    event_type=event_type,
                    description=f'Account {"locked" if instance.account_locked else "unlocked"}',
                    metadata={
                        'previous_state': old_profile.account_locked,
                        'new_state': instance.account_locked,
                        'lock_reason': instance.lock_reason
                    }
                )

            # Verificar cambios en verificación de correo
            if old_profile.email_verified != instance.email_verified:
                event_type = 'EMAIL_VERIFIED' if instance.email_verified else 'EMAIL_UNVERIFIED'
                SecurityLog.objects.create(
                    user=instance.user,
                    event_type=event_type,
                    description=f'Email verification status changed',
                    metadata={
                        'previous_state': old_profile.email_verified,
                        'new_state': instance.email_verified
                    }
                )

        except UserProfile.DoesNotExist:
            pass


@receiver(post_delete, sender=SessionManagement)
def log_session_termination(sender, instance, **kwargs):
    """
    Señal para registrar terminación de sesiones.
    """
    if instance.is_active:
        SecurityLog.objects.create(
            user=instance.user,
            event_type='SESSION_TERMINATED',
            description=f'Session terminated for user {instance.user.username}',
            metadata={
                'ip_address': instance.ip_address,
                'user_agent': instance.user_agent[:50] if instance.user_agent else '',
                'session_key': instance.session_key,
                'terminated_manually': not instance.is_active
            }
        )


def connect_signals():
    """
    Función para conectar todas las señales manualmente si es necesario.

    Esto puede ser útil en situaciones donde las señales no se conectan
    automáticamente (por ejemplo, en aplicaciones de terceros).
    """
    # Las señales ya están conectadas mediante los decoradores @receiver
    # Esta función es para propósitos de compatibilidad
    pass


def disconnect_signals():
    """
    Función para desconectar todas las señales si es necesario.

    Esto puede ser útil durante pruebas o configuraciones especiales.
    """
    # Desconectar señales específicas si es necesario
    pass


# Configuración de frecuencia de limpieza automática
CLEANUP_FREQUENCY_HOURS = getattr(settings, 'AUTHO_CORE_CLEANUP_FREQUENCY_HOURS', 24)


def cleanup_old_logs():
    """
    Función para limpiar registros antiguos de seguridad.

    Debe ser llamada periódicamente (por ejemplo, mediante Celery o Django management command).
    """
    from datetime import timedelta

    # Configuración de retención
    max_age_hours = getattr(settings, 'AUTHO_CORE_MAX_LOG_AGE_HOURS', 720)  # 30 días por defecto

    cutoff_time = timezone.now() - timedelta(hours=max_age_hours)

    # Limpiar SecurityLogs antiguos
    SecurityLog.objects.filter(timestamp__lt=cutoff_time).delete()

    # Limpiar FailedLoginAttempts antiguos
    FailedLoginAttempt.objects.filter(attempt_time__lt=cutoff_time).delete()

    # Limpiar SessionManagement inactivas antiguas
    SessionManagement.objects.filter(
        is_active=False,
        last_activity__lt=cutoff_time
    ).delete()


def get_security_stats(user=None):
    """
    Obtener estadísticas de seguridad.

    Args:
        user: Usuario específico (opcional)

    Returns:
        dict: Diccionario con estadísticas de seguridad
    """
    from datetime import timedelta

    # Definir períodos de tiempo
    now = timezone.now()
    last_hour = now - timedelta(hours=1)
    last_day = now - timedelta(days=1)
    last_week = now - timedelta(weeks=1)

    # Base query
    base_query = SecurityLog.objects.all()
    if user:
        base_query = base_query.filter(user=user)

    # Contar eventos por período
    stats = {
        'last_hour': base_query.filter(timestamp__gte=last_hour).count(),
        'last_day': base_query.filter(timestamp__gte=last_day).count(),
        'last_week': base_query.filter(timestamp__gte=last_week).count(),
        'total': base_query.count(),
    }

    # Contar eventos por tipo
    event_types = SecurityLog.EVENT_TYPES
    for event_code, event_name in event_types:
        stats[f'{event_code.lower()}_count'] = base_query.filter(
            event_type=event_code
        ).count()

    # Intentos fallidos de login
    failed_attempts = FailedLoginAttempt.objects.filter(
        timestamp__gte=last_day
    )
    if user:
        # Para un usuario específico, buscar por username
        failed_attempts = failed_attempts.filter(username__iexact=user.username)

    stats['failed_login_attempts_last_day'] = failed_attempts.count()

    # Sesiones activas
    active_sessions = SessionManagement.objects.filter(is_active=True)
    if user:
        active_sessions = active_sessions.filter(user=user)

    stats['active_sessions'] = active_sessions.count()

    return stats


def notify_security_events(user, event_types=None, notification_method='email'):
    """
    Enviar notificaciones sobre eventos de seguridad.

    Args:
        user: Usuario a notificar
        event_types: Lista de tipos de eventos a notificar (None para todos)
        notification_method: Método de notificación ('email', 'sms', 'push')
    """
    base_query = SecurityLog.objects.filter(user=user)

    if event_types:
        base_query = base_query.filter(event_type__in=event_types)

    # Obtener eventos no notificados (suponiendo que tengamos un campo para esto)
    # Aquí implementaríamos la lógica de notificación

    pass


def setup_custom_signals():
    """
    Configurar señales personalizadas para Autho Core.

    Este método permite registrar manejadores personalizados para
    eventos específicos de seguridad.
    """
    # Aquí podríamos agregar señales personalizadas adicionales
    # como "mfa_enabled", "password_changed", "profile_updated", etc.
    pass