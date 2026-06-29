"""
Modelos de autenticación y seguridad para Autho Core

Este módulo contiene los modelos extendidos para funcionalidades de seguridad
adicional más allá del modelo User estándar de Django.
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
import uuid


class UserProfile(models.Model):
    """
    Perfil extendido del usuario con funcionalidades de seguridad adicionales.
    """

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile',
        verbose_name=_('Usuario')
    )

    # Verificación de correo electrónico
    email_verified = models.BooleanField(
        default=False,
        verbose_name=_('Correo verificado')
    )

    # Autenticación de dos factores
    mfa_enabled = models.BooleanField(
        default=False,
        verbose_name=_('2FA habilitado')
    )

    mfa_secret = models.CharField(
        max_length=32,
        blank=True,
        null=True,
        verbose_name=_('Secreto 2FA')
    )

    # Información de sesión
    last_login_ip = models.GenericIPAddressField(
        blank=True,
        null=True,
        verbose_name=_('Última IP de login')
    )

    current_login_ip = models.GenericIPAddressField(
        blank=True,
        null=True,
        verbose_name=_('IP de login actual')
    )

    last_user_agent = models.TextField(
        blank=True,
        verbose_name=_('Último user agent')
    )

    current_user_agent = models.TextField(
        blank=True,
        verbose_name=_('User agent actual')
    )

    # Configuraciones de seguridad
    password_changed_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('Fecha cambio contraseña')
    )

    require_password_change = models.BooleanField(
        default=False,
        verbose_name=_('Requiere cambio de contraseña')
    )

    account_locked = models.BooleanField(
        default=False,
        verbose_name=_('Cuenta bloqueada')
    )

    lock_reason = models.TextField(
        blank=True,
        verbose_name=_('Motivo del bloqueo')
    )

    locked_until = models.DateTimeField(
        blank=True,
        null=True,
        verbose_name=_('Bloqueado hasta')
    )

    # Prefijos del usuario
    language = models.CharField(
        max_length=10,
        default='es',
        verbose_name=_('Idioma')
    )

    timezone_str = models.CharField(
        max_length=50,
        default='UTC',
        verbose_name=_('Zona horaria')
    )

    # Metadatos
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('Fecha de creación')
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name=_('Fecha de actualización')
    )

    class Meta:
        verbose_name = _('Perfil de usuario')
        verbose_name_plural = _('Perfiles de usuario')
        ordering = ['-created_at']

    def __str__(self):
        return f"Perfil de {self.user.username}"

    def is_locked(self):
        """
        Verificar si la cuenta está actualmente bloqueada.
        """
        if not self.account_locked:
            return False

        if self.locked_until and self.locked_until < timezone.now():
            # El bloqueo ha expirado
            self.account_locked = False
            self.locked_until = None
            self.save()
            return False

        return True

    def lock_account(self, reason=None, duration_minutes=None):
        """
        Bloquear la cuenta del usuario.
        """
        self.account_locked = True
        self.lock_reason = reason or 'Bloqueo automático por seguridad'

        if duration_minutes:
            self.locked_until = timezone.now() + timezone.timedelta(minutes=duration_minutes)
        else:
            self.locked_until = None

        self.save()

    def unlock_account(self):
        """
        Desbloquear la cuenta del usuario.
        """
        self.account_locked = False
        self.lock_reason = ''
        self.locked_until = None
        self.save()


class FailedLoginAttempt(models.Model):
    """
    Registro de intentos fallidos de inicio de sesión.
    """

    username = models.CharField(
        max_length=150,
        db_index=True,
        verbose_name=_('Usuario')
    )

    ip_address = models.GenericIPAddressField(
        verbose_name=_('Dirección IP')
    )

    user_agent = models.TextField(
        blank=True,
        verbose_name=_('User Agent')
    )

    attempt_time = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('Hora del intento')
    )

    success = models.BooleanField(
        default=False,
        verbose_name=_('Exitoso')
    )

    failure_reason = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_('Motivo del fallo')
    )

    # Identificación del dispositivo (fingerprint)
    device_fingerprint = models.CharField(
        max_length=64,
        blank=True,
        verbose_name=_('Huella del dispositivo')
    )

    class Meta:
        verbose_name = _('Intento de login fallido')
        verbose_name_plural = _('Intentos de login fallidos')
        ordering = ['-attempt_time']
        indexes = [
            models.Index(fields=['username', '-attempt_time']),
            models.Index(fields=['ip_address', '-attempt_time']),
        ]

    def __str__(self):
        return f"Intento fallido: {self.username} desde {self.ip_address}"

    @classmethod
    def get_recent_attempts(cls, username, minutes=15):
        """
        Obtener intentos recientes para un usuario.
        """
        time_threshold = timezone.now() - timezone.timedelta(minutes=minutes)
        return cls.objects.filter(
            username__iexact=username,
            attempt_time__gte=time_threshold
        )

    @classmethod
    def get_ip_attempts(cls, ip_address, minutes=15):
        """
        Obtener intentos recientes desde una dirección IP.
        """
        time_threshold = timezone.now() - timezone.timedelta(minutes=minutes)
        return cls.objects.filter(
            ip_address=ip_address,
            attempt_time__gte=time_threshold
        )


class SecurityLog(models.Model):
    """
    Registro de eventos de seguridad para auditoría.
    """

    EVENT_TYPES = [
        ('LOGIN_SUCCESS', _('Inicio de sesión exitoso')),
        ('LOGIN_FAILED', _('Inicio de sesión fallido')),
        ('LOGOUT', _('Cierre de sesión')),
        ('REGISTRATION', _('Registro de usuario')),
        ('PASSWORD_CHANGE', _('Cambio de contraseña')),
        ('PASSWORD_RESET', _('Restablecimiento de contraseña')),
        ('EMAIL_VERIFIED', _('Correo verificado')),
        ('MFA_ENABLED', _('2FA habilitado')),
        ('MFA_DISABLED', _('2FA deshabilitado')),
        ('MFA_VERIFIED', _('2FA verificado')),
        ('PROFILE_UPDATE', _('Actualización de perfil')),
        ('BACKUP_CODES_GENERATED', _('Códigos de respaldo generados')),
        ('ACCOUNT_LOCKED', _('Cuenta bloqueada')),
        ('ACCOUNT_UNLOCKED', _('Cuenta desbloqueada')),
        ('SUSPICIOUS_ACTIVITY', _('Actividad sospechosa')),
        ('OTHER', _('Otro evento')),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='security_logs',
        verbose_name=_('Usuario')
    )

    event_type = models.CharField(
        max_length=50,
        choices=EVENT_TYPES,
        verbose_name=_('Tipo de evento')
    )

    description = models.TextField(
        verbose_name=_('Descripción')
    )

    ip_address = models.GenericIPAddressField(
        blank=True,
        null=True,
        verbose_name=_('Dirección IP')
    )

    user_agent = models.TextField(
        blank=True,
        verbose_name=_('User Agent')
    )

    timestamp = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('Timestamp')
    )

    metadata = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_('Metadatos')
    )

    # Información geográfica (opcional)
    country = models.CharField(
        max_length=100,
        blank=True,
        verbose_name=_('País')
    )

    city = models.CharField(
        max_length=100,
        blank=True,
        verbose_name=_('Ciudad')
    )

    class Meta:
        verbose_name = _('Registro de seguridad')
        verbose_name_plural = _('Registros de seguridad')
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['event_type', '-timestamp']),
            models.Index(fields=['ip_address', '-timestamp']),
        ]

    def __str__(self):
        user_str = self.user.username if self.user else 'Unknown'
        return f"{self.get_event_type_display()}: {user_str} - {self.timestamp}"

    @classmethod
    def log_event(cls, user, event_type, request=None, description=None, metadata=None):
        """
        Registrar un evento de seguridad.
        """
        ip_address = None
        user_agent = None

        if request:
            # Obtener la dirección IP real (considerando proxies)
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0].strip()
            else:
                ip_address = request.META.get('REMOTE_ADDR')

            user_agent = request.META.get('HTTP_USER_AGENT', '')

        return cls.objects.create(
            user=user,
            event_type=event_type,
            description=description or f'{event_type} event',
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {}
        )


class BackupCode(models.Model):
    """
    Códigos de respaldo para autenticación de dos factores.
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='backup_codes',
        verbose_name=_('Usuario')
    )

    code = models.CharField(
        max_length=10,
        unique=True,
        verbose_name=_('Código')
    )

    is_used = models.BooleanField(
        default=False,
        verbose_name=_('Usado')
    )

    used_at = models.DateTimeField(
        blank=True,
        null=True,
        verbose_name=_('Fecha de uso')
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('Fecha de creación')
    )

    class Meta:
        verbose_name = _('Código de respaldo')
        verbose_name_plural = _('Códigos de respaldo')
        ordering = ['-created_at']

    def __str__(self):
        return f"Backup code for {self.user.username}"

    def mark_as_used(self):
        """
        Marcar el código como usado.
        """
        self.is_used = True
        self.used_at = timezone.now()
        self.save()

    @classmethod
    def generate_backup_codes(cls, user, count=10):
        """
        Generar códigos de respaldo para un usuario.
        """
        import secrets
        import string

        codes = []
        for _ in range(count):
            # Generar código de 8 caracteres
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            code = f"{code[:4]}-{code[4:]}"

            # Crear y guardar el código
            backup_code = cls.objects.create(user=user, code=code)
            codes.append(backup_code.code)

        return codes

    @classmethod
    def validate_backup_code(cls, user, code):
        """
        Validar y consumir un código de respaldo.
        """
        backup_code = cls.objects.filter(
            user=user,
            code=code,
            is_used=False
        ).first()

        if backup_code:
            backup_code.mark_as_used()
            return True

        return False


class SessionManagement(models.Model):
    """
    Gestión de sesiones activas de usuario.
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sessions',
        verbose_name=_('Usuario')
    )

    session_key = models.CharField(
        max_length=40,
        unique=True,
        verbose_name=_('Clave de sesión')
    )

    ip_address = models.GenericIPAddressField(
        verbose_name=_('Dirección IP')
    )

    user_agent = models.TextField(
        verbose_name=_('User Agent')
    )

    device_fingerprint = models.CharField(
        max_length=64,
        blank=True,
        verbose_name=_('Huella del dispositivo')
    )

    is_current = models.BooleanField(
        default=False,
        verbose_name=_('Sesión actual')
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_('Fecha de creación')
    )

    last_activity = models.DateTimeField(
        auto_now=True,
        verbose_name=_('Última actividad')
    )

    is_active = models.BooleanField(
        default=True,
        verbose_name=_('Activa')
    )

    class Meta:
        verbose_name = _('Gestión de sesión')
        verbose_name_plural = _('Gestión de sesiones')
        ordering = ['-last_activity']

    def __str__(self):
        return f"Sesión de {self.user.username} desde {self.ip_address}"

    def terminate(self):
        """
        Terminar esta sesión.
        """
        self.is_active = False
        self.save()

    @classmethod
    def terminate_all_user_sessions(cls, user, exclude_current=False):
        """
        Terminar todas las sesiones de un usuario.
        """
        sessions = cls.objects.filter(user=user, is_active=True)

        if exclude_current:
            sessions = sessions.exclude(is_current=True)

        sessions.update(is_active=False)
        return sessions.count()