from django.apps import AppConfig


class CapstoneProjectConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'capstone_project'

    def ready(self):
        """Import signal handlers when the app is ready."""
        import capstone_project.signals
