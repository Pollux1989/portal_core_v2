from django.db import models
from django.contrib.auth.models import User


class Profile(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE
    )

    display_name = models.CharField(
        max_length=100,
        blank=True
    )

    theme = models.CharField(
        max_length=50,
        default="matrix"
    )

    bio = models.TextField(
        blank=True
    )

    def __str__(self):
        return self.user.username