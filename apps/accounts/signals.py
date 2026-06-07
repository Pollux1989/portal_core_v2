from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.contrib.auth.models import User


@receiver(pre_save, sender=User)
def normalize_email(sender, instance, **kwargs):

    if instance.email:
        instance.email = instance.email.strip().lower()