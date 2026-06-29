"""
Configuración de administración para Autho Core

Este módulo contiene la configuración del panel de administración de Django
para los modelos de seguridad y autenticación.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from django.utils.html import format_html
from django.utils import timezone
from django.db.models import Count, Q
from django.urls import reverse
from django.utils.safestring import mark_safe

from .models import (
    UserProfile, FailedLoginAttempt, SecurityLog,
    BackupCode, SessionManagement
)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """
    Panel de administración para perfiles de usuario.
    """
    list_display = [
        'user', 'email_verified', 'mfa_enabled',
        'account_locked', 'last_login_ip', 'created_at'
    ]
    list_filter = [
        'email_verified', 'mfa_enabled', 'account_locked',
        'language', 'timezone_str', 'created_at'
    ]
    search_fields = [
        'user__username', 'user__email', 'user__first_name',
        'user__last_name', 'last_login_ip', 'current_login_ip'
    ]
    readonly_fields = [
        'created_at', 'updated_at', 'password_changed_at',
        'last_login_ip', 'current_login_ip', 'last_user_agent',
        'current_user_agent'
    ]
    fieldsets = (
        ('Información del Usuario', {
            'fields': ('user', 'email_verified')
        }),
        ('Autenticación de Dos Factores', {
            'fields': ('mfa_enabled', 'mfa_secret')
        }),
        ('Información de Sesión', {
            'fields': (
                'last_login_ip', 'current_login_ip',
                'last_user_agent', 'current_user_agent'
            )
        }),
        ('Estado de la Cuenta', {
            'fields': (
                'account_locked', 'lock_reason', 'locked_until',
                'require_password_change', 'password_changed_at'
            )
        }),
        ('Preferencias', {
            'fields': ('language', 'timezone_str')
        }),
        ('Metadatos', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    actions = ['unlock_accounts', 'disable_mfa', 'require_password_change']

    def unlock_accounts(self, request, queryset):
        """
        Acción para desbloquear cuentas seleccionadas.
        """
        updated = queryset.filter(account_locked=True).update(
            account_locked=False,
            lock_reason='',
            locked_until=None
        )
        self.message_user(
            request,
            f'{updated} cuentas desbloqueadas exitosamente.'
        )
    unlock_accounts.short_description = 'Desbloquear cuentas seleccionadas'

    def disable_mfa(self, request, queryset):
        """
        Acción para deshabilitar 2FA en cuentas seleccionadas.
        """
        updated = queryset.filter(mfa_enabled=True).update(
            mfa_enabled=False,
            mfa_secret=None
        )
        self.message_user(
            request,
            f'2FA deshabilitado en {updated} cuentas.'
        )
    disable_mfa.short_description = 'Deshabilitar 2FA en cuentas seleccionadas'

    def require_password_change(self, request, queryset):
        """
        Acción para requerir cambio de contraseña en cuentas seleccionadas.
        """
        updated = queryset.update(require_password_change=True)
        self.message_user(
            request,
            f'{updated} usuarios requeridos para cambiar contraseña.'
        )
    require_password_change.short_description = 'Requerir cambio de contraseña'


@admin.register(FailedLoginAttempt)
class FailedLoginAttemptAdmin(admin.ModelAdmin):
    """
    Panel de administración para intentos fallidos de login.
    """
    list_display = [
        'username', 'ip_address', 'attempt_time',
        'success', 'failure_reason', 'device_fingerprint'
    ]
    list_filter = [
        'success', 'attempt_time', 'failure_reason'
    ]
    search_fields = [
        'username', 'ip_address', 'user_agent',
        'device_fingerprint', 'failure_reason'
    ]
    readonly_fields = [
        'username', 'ip_address', 'user_agent',
        'attempt_time', 'success', 'failure_reason',
        'device_fingerprint'
    ]
    date_hierarchy = 'attempt_time'
    actions = ['delete_old_attempts']

    def delete_old_attempts(self, request, queryset):
        """
        Acción para eliminar intentos antiguos (más de 30 días).
        """
        from datetime import timedelta
        cutoff = timezone.now() - timedelta(days=30)
        deleted = queryset.filter(attempt_time__lt=cutoff).delete()[0]
        self.message_user(
            request,
            f'{deleted} intentos antiguos eliminados.'
        )
    delete_old_attempts.short_description = 'Eliminar intentos de hace más de 30 días'


@admin.register(SecurityLog)
class SecurityLogAdmin(admin.ModelAdmin):
    """
    Panel de administración para registros de seguridad.
    """
    list_display = [
        'user', 'event_type', 'description',
        'ip_address', 'timestamp', 'country'
    ]
    list_filter = [
        'event_type', 'timestamp', 'country'
    ]
    search_fields = [
        'user__username', 'user__email',
        'ip_address', 'description', 'user_agent'
    ]
    readonly_fields = [
        'user', 'event_type', 'description',
        'ip_address', 'user_agent', 'timestamp',
        'metadata', 'country', 'city'
    ]
    date_hierarchy = 'timestamp'
    actions = ['delete_old_logs', 'export_logs']

    def has_add_permission(self, request):
        """
        No permitir agregar registros manualmente.
        """
        return False

    def has_change_permission(self, request, obj=None):
        """
        No permitir modificar registros existentes.
        """
        return False

    def delete_old_logs(self, request, queryset):
        """
        Acción para eliminar registros antiguos (más de 90 días).
        """
        from datetime import timedelta
        cutoff = timezone.now() - timedelta(days=90)
        deleted = queryset.filter(timestamp__lt=cutoff).delete()[0]
        self.message_user(
            request,
            f'{deleted} registros antiguos eliminados.'
        )
    delete_old_logs.short_description = 'Eliminar registros de hace más de 90 días'

    def export_logs(self, request, queryset):
        """
        Acción para exportar registros a CSV.
        """
        import csv
        from django.http import HttpResponse

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="security_logs.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'User', 'Event Type', 'Description', 'IP Address',
            'User Agent', 'Timestamp', 'Country', 'City'
        ])

        for log in queryset:
            writer.writerow([
                log.user.username if log.user else 'Unknown',
                log.event_type,
                log.description,
                log.ip_address,
                log.user_agent[:50] if log.user_agent else '',
                log.timestamp,
                log.country,
                log.city
            ])

        return response
    export_logs.short_description = 'Exportar registros seleccionados a CSV'


@admin.register(BackupCode)
class BackupCodeAdmin(admin.ModelAdmin):
    """
    Panel de administración para códigos de respaldo.
    """
    list_display = [
        'user', 'code_masked', 'is_used',
        'used_at', 'created_at'
    ]
    list_filter = [
        'is_used', 'created_at', 'used_at'
    ]
    search_fields = [
        'user__username', 'user__email'
    ]
    readonly_fields = [
        'user', 'code', 'is_used', 'used_at', 'created_at'
    ]
    date_hierarchy = 'created_at'

    def code_masked(self, obj):
        """
        Mostrar el código parcialmente oculto.
        """
        if obj.code:
            return f"****-{obj.code.split('-')[1] if '-' in obj.code else '****'}"
        return 'N/A'
    code_masked.short_description = 'Código'

    def has_add_permission(self, request):
        """
        No permitir agregar códigos manualmente.
        """
        return False

    def has_change_permission(self, request, obj=None):
        """
        No permitir modificar códigos existentes.
        """
        return False


@admin.register(SessionManagement)
class SessionManagementAdmin(admin.ModelAdmin):
    """
    Panel de administración para gestión de sesiones.
    """
    list_display = [
        'user', 'session_key_short', 'ip_address',
        'is_current', 'is_active', 'last_activity'
    ]
    list_filter = [
        'is_current', 'is_active', 'last_activity'
    ]
    search_fields = [
        'user__username', 'user__email',
        'ip_address', 'session_key'
    ]
    readonly_fields = [
        'user', 'session_key', 'ip_address',
        'user_agent', 'device_fingerprint',
        'is_current', 'is_active', 'created_at',
        'last_activity'
    ]
    date_hierarchy = 'last_activity'
    actions = ['terminate_sessions', 'terminate_all_user_sessions']

    def session_key_short(self, obj):
        """
        Mostrar clave de sesión acortada.
        """
        if obj.session_key:
            return f"{obj.session_key[:8]}..."
        return 'N/A'
    session_key_short.short_description = 'Clave de sesión'

    def terminate_sessions(self, request, queryset):
        """
        Acción para terminar sesiones seleccionadas.
        """
        updated = queryset.filter(is_active=True).update(is_active=False)
        self.message_user(
            request,
            f'{updated} sesiones terminadas exitosamente.'
        )
    terminate_sessions.short_description = 'Terminar sesiones seleccionadas'

    def terminate_all_user_sessions(self, request, queryset):
        """
        Acción para terminar todas las sesiones de los usuarios seleccionados.
        """
        users = queryset.values_list('user', flat=True).distinct()
        updated = SessionManagement.objects.filter(
            user__in=users,
            is_active=True
        ).update(is_active=False)

        self.message_user(
            request,
            f'{updated} sesiones terminadas para {len(users)} usuarios.'
        )
    terminate_all_user_sessions.short_description = 'Terminar todas las sesiones de los usuarios'


# Extender el UserAdmin estándar
class UserProfileInline(admin.StackedInline):
    """
    Inline para mostrar el perfil de usuario en el panel de administración de usuarios.
    """
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Perfil de Seguridad'
    readonly_fields = [
        'email_verified', 'mfa_enabled', 'account_locked',
        'last_login_ip', 'current_login_ip', 'created_at'
    ]
    fieldsets = (
        ('Información de Seguridad', {
            'fields': (
                'email_verified', 'mfa_enabled', 'account_locked',
                'last_login_ip', 'current_login_ip'
            )
        }),
    )


class UserAdmin(BaseUserAdmin):
    """
    Panel de administración extendido para usuarios.
    """
    inlines = [UserProfileInline]
    list_display = [
        'username', 'email', 'first_name', 'last_name',
        'is_staff', 'is_active', 'date_joined', 'get_security_status'
    ]
    list_filter = [
        'is_staff', 'is_superuser', 'is_active',
        'groups', 'date_joined'
    ]

    def get_security_status(self, obj):
        """
        Mostrar estado de seguridad del usuario.
        """
        try:
            profile = obj.profile
            status_parts = []

            if profile.email_verified:
                status_parts.append('✓ Email')
            else:
                status_parts.append('✗ Email')

            if profile.mfa_enabled:
                status_parts.append('✓ 2FA')
            else:
                status_parts.append('✗ 2FA')

            if profile.account_locked:
                status_parts.append('🔒 Bloqueado')

            return ' | '.join(status_parts)
        except UserProfile.DoesNotExist:
            return 'Sin perfil'
    get_security_status.short_description = 'Estado de Seguridad'

    def get_queryset(self, request):
        """
        Optimizar consultas con prefetch_related.
        """
        qs = super().get_queryset(request)
        return qs.select_related('profile')


# Reemplazar el UserAdmin estándar
admin.site.unregister(User)
admin.site.register(User, UserAdmin)


# Personalizar el panel de administración
class AuthoCoreAdminSite(admin.AdminSite):
    """
    Sitio de administración personalizado para Autho Core.
    """
    site_header = 'Autho Core Administration'
    site_title = 'Autho Core Admin'
    index_title = 'Welcome to Autho Core Administration'

    def get_urls(self):
        """
        Agregar URLs personalizadas al panel de administración.
        """
        from django.urls import path
        urls = super().get_urls()
        custom_urls = [
            path('security-dashboard/', self.admin_view(self.security_dashboard),
                 name='security_dashboard'),
        ]
        return custom_urls + urls

    def security_dashboard(self, request):
        """
        Vista personalizada del dashboard de seguridad.
        """
        from django.template.response import TemplateResponse

        # Obtener estadísticas
        total_users = User.objects.count()
        active_users = User.objects.filter(is_active=True).count()
        verified_users = UserProfile.objects.filter(email_verified=True).count()
        mfa_users = UserProfile.objects.filter(mfa_enabled=True).count()
        locked_accounts = UserProfile.objects.filter(account_locked=True).count()

        # Intentos fallidos recientes
        from datetime import timedelta
        recent_failed = FailedLoginAttempt.objects.filter(
            attempt_time__gte=timezone.now() - timedelta(days=1)
        ).count()

        # Sesiones activas
        active_sessions = SessionManagement.objects.filter(is_active=True).count()

        # Eventos de seguridad recientes
        recent_events = SecurityLog.objects.filter(
            timestamp__gte=timezone.now() - timedelta(days=1)
        ).count()

        context = {
            **self.each_context(request),
            'title': 'Security Dashboard',
            'stats': {
                'total_users': total_users,
                'active_users': active_users,
                'verified_users': verified_users,
                'mfa_users': mfa_users,
                'locked_accounts': locked_accounts,
                'recent_failed': recent_failed,
                'active_sessions': active_sessions,
                'recent_events': recent_events,
            }
        }

        return TemplateResponse(request, 'admin/security_dashboard.html', context)


# Crear instancia del sitio de administración personalizado
autho_core_admin = AuthoCoreAdminSite(name='autho_core_admin')