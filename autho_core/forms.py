"""
Formularios de autenticación y seguridad para Autho Core

Este módulo contiene todos los formularios necesarios para el sistema de
autenticación, incluyendo login, registro, gestión de contraseñas y perfil.
"""

from django import forms
from django.contrib.auth.forms import (
    AuthenticationForm, PasswordResetForm, PasswordChangeForm, SetPasswordForm
)
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.core.validators import validate_email
from django.utils.regex_helper import _lazy_re_compile
import re


class LoginForm(AuthenticationForm):
    """
    Formulario de inicio de sesión con validaciones mejoradas.
    """

    username = forms.CharField(
        label=_('Usuario o correo'),
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Usuario o correo electrónico',
            'autofocus': True
        })
    )
    password = forms.CharField(
        label=_('Contraseña'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Contraseña'
        })
    )
    remember_me = forms.BooleanField(
        label=_('Recordarme'),
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        })
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs['class'] = 'form-control'
        self.fields['password'].widget.attrs['class'] = 'form-control'


class RegistrationForm(forms.ModelForm):
    """
    Formulario de registro de nuevos usuarios con validaciones de seguridad.
    """

    username = forms.CharField(
        label=_('Nombre de usuario'),
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nombre de usuario'
        }),
        help_text=_('Requerido. 150 caracteres o menos. Letras, dígitos y @/./+/-/_ solamente.')
    )

    email = forms.EmailField(
        label=_('Correo electrónico'),
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'correo@ejemplo.com'
        }),
        help_text=_('Introduzca un correo electrónico válido.')
    )

    password1 = forms.CharField(
        label=_('Contraseña'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Contraseña'
        }),
        help_text=_('La contraseña debe tener al menos 8 caracteres e incluir mayúsculas, minúsculas y números.')
    )

    password2 = forms.CharField(
        label=_('Confirmar contraseña'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirmar contraseña'
        }),
        help_text=_('Introduzca la misma contraseña que arriba para verificación.')
    )

    first_name = forms.CharField(
        label=_('Nombre'),
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nombre'
        }),
        required=False
    )

    last_name = forms.CharField(
        label=_('Apellidos'),
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Apellidos'
        }),
        required=False
    )

    terms_and_conditions = forms.BooleanField(
        label=_('Acepto los términos y condiciones'),
        required=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        })
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name')

    def clean_username(self):
        """
        Validar que el nombre de usuario sea único y cumpla con los requisitos.
        """
        username = self.cleaned_data.get('username')

        # Validar longitud
        if len(username) < 3:
            raise ValidationError(_('El nombre de usuario debe tener al menos 3 caracteres.'))

        # Validar formato
        if not re.match(r'^[\w.@+-]+$', username):
            raise ValidationError(_('El nombre de usuario solo puede contener letras, dígitos y @/./+/-/_.'))

        # Verificar unicidad
        User = get_user_model()
        if User.objects.filter(username__iexact=username).exists():
            raise ValidationError(_('Este nombre de usuario ya está en uso.'))

        return username

    def clean_email(self):
        """
        Validar que el correo electrónico sea único y válido.
        """
        email = self.cleaned_data.get('email')

        # Validar formato
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError(_('Introduzca un correo electrónico válido.'))

        # Verificar unicidad (case-insensitive)
        User = get_user_model()
        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError(_('Este correo electrónico ya está registrado.'))

        return email.lower()  # Normalizar a minúsculas

    def clean_password1(self):
        """
        Validar la fortaleza de la contraseña.
        """
        password = self.cleaned_data.get('password1')

        if len(password) < 8:
            raise ValidationError(_('La contraseña debe tener al menos 8 caracteres.'))

        # Validar mayúsculas y minúsculas
        if not re.search(r'[A-Z]', password):
            raise ValidationError(_('La contraseña debe contener al menos una letra mayúscula.'))

        if not re.search(r'[a-z]', password):
            raise ValidationError(_('La contraseña debe contener al menos una letra minúscula.'))

        # Validar números
        if not re.search(r'\d', password):
            raise ValidationError(_('La contraseña debe contener al menos un número.'))

        # Validar caracteres especiales (opcional)
        # if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        #     raise ValidationError(_('La contraseña debe contener al menos un carácter especial.'))

        return password

    def clean_password2(self):
        """
        Validar que las contraseñas coincidan.
        """
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise ValidationError(_('Las contraseñas no coinciden.'))

        return password2

    def save(self, commit=True):
        """
        Guardar el usuario con la contraseña encriptada.
        """
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])

        if commit:
            user.save()

        return user


class ProfileForm(forms.ModelForm):
    """
    Formulario para editar el perfil de usuario.
    """

    username = forms.CharField(
        label=_('Nombre de usuario'),
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'readonly': 'readonly'
        }),
        disabled=True,
        help_text=_('El nombre de usuario no puede ser modificado.')
    )

    email = forms.EmailField(
        label=_('Correo electrónico'),
        widget=forms.EmailInput(attrs={
            'class': 'form-control'
        }),
        help_text=_('Introduzca un correo electrónico válido.')
    )

    first_name = forms.CharField(
        label=_('Nombre'),
        widget=forms.TextInput(attrs={
            'class': 'form-control'
        }),
        required=False
    )

    last_name = forms.CharField(
        label=_('Apellidos'),
        widget=forms.TextInput(attrs={
            'class': 'form-control'
        }),
        required=False
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name')

    def clean_email(self):
        """
        Validar que el nuevo correo electrónico sea único.
        """
        email = self.cleaned_data.get('email')

        # Validar formato
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError(_('Introduzca un correo electrónico válido.'))

        # Verificar unicidad (excluyendo el usuario actual)
        User = get_user_model()
        if User.objects.filter(email__iexact=email).exclude(pk=self.instance.pk).exists():
            raise ValidationError(_('Este correo electrónico ya está en uso.'))

        return email.lower()


class PasswordChangeForm(PasswordChangeForm):
    """
    Formulario para cambiar la contraseña con validaciones mejoradas.
    """

    old_password = forms.CharField(
        label=_('Contraseña actual'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'autofocus': True
        })
    )

    new_password1 = forms.CharField(
        label=_('Nueva contraseña'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control'
        }),
        help_text=_('La contraseña debe tener al menos 8 caracteres e incluir mayúsculas, minúsculas y números.')
    )

    new_password2 = forms.CharField(
        label=_('Confirmar nueva contraseña'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control'
        }),
        help_text=_('Introduzca la misma contraseña que arriba para verificación.')
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['old_password'].widget.attrs['class'] = 'form-control'
        self.fields['new_password1'].widget.attrs['class'] = 'form-control'
        self.fields['new_password2'].widget.attrs['class'] = 'form-control'


class CustomPasswordResetForm(PasswordResetForm):
    """
    Formulario personalizado para recuperación de contraseña.
    """

    email = forms.EmailField(
        label=_('Correo electrónico'),
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Introduzca su correo electrónico',
            'autofocus': True
        }),
        max_length=254
    )


class MFAVerifyForm(forms.Form):
    """
    Formulario para verificar el código de autenticación de dos factores.
    """

    code = forms.CharField(
        label=_('Código de verificación'),
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Código de 6 dígitos',
            'maxlength': 6,
            'autofocus': True,
            'pattern': '[0-9]{6}',
            'inputmode': 'numeric'
        }),
        max_length=6,
        min_length=6
    )

    def clean_code(self):
        """
        Validar que el código tenga el formato correcto.
        """
        code = self.cleaned_data.get('code')

        if not code.isdigit() or len(code) != 6:
            raise ValidationError(_('El código debe ser de 6 dígitos numéricos.'))

        return code


class MFADisableForm(forms.Form):
    """
    Formulario para deshabilitar la autenticación de dos factores.
    """

    code = forms.CharField(
        label=_('Código de verificación'),
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Código de 6 dígitos',
            'maxlength': 6,
            'autofocus': True,
            'pattern': '[0-9]{6}',
            'inputmode': 'numeric'
        }),
        max_length=6,
        min_length=6,
        help_text=_('Introduzca el código de su aplicación de autenticación para confirmar.')
    )

    confirm_disable = forms.BooleanField(
        label=_('Confirmar que desea deshabilitar 2FA'),
        required=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        })
    )

    def clean_code(self):
        """
        Validar que el código tenga el formato correcto.
        """
        code = self.cleaned_data.get('code')

        if not code.isdigit() or len(code) != 6:
            raise ValidationError(_('El código debe ser de 6 dígitos numéricos.'))

        return code