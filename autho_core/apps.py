from django.apps import AppConfig


class AuthoCoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'autho_core'
    verbose_name = 'Authentication Core'
    verbose_name_plural = 'Authentication Core'

    def ready(self):
        """
        Método que se ejecuta cuando la aplicación está lista.
        Se puede usar para registrar señales o configuraciones adicionales.
        """
        try:
            import autho_core.signals  # noqa
        except ImportError:
            pass