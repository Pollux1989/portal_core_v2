from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.password_validation import validate_password

class LoginForm(AuthenticationForm):
    pass


class RegisterForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(),
        validators=[validate_password],
        help_text="Password must be at least 8 characters long and contain a mix of letters, numbers, and special characters."
    )

    password_confirm = forms.CharField(
        widget=forms.PasswordInput()
    )

    class Meta:
        model = User
        fields = [
            "username",
            "email",
            "password",
        ]

    def clean(self):
        cleaned_data = super().clean()

        password = cleaned_data.get("password")
        confirm = cleaned_data.get("password_confirm")

        if password != confirm:
            raise forms.ValidationError(
                "Passwords do not match."
            )

        return cleaned_data

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError(
                "A user with that email already exists."
            )
        return email   
       