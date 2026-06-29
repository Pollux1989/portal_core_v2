"""
Vistas de autenticación y seguridad para Autho Core

Este módulo contiene todas las vistas necesarias para un sistema de autenticación
completo y seguro, incluyendo login, logout, registro, gestión de contraseñas,
perfil de usuario y funciones de seguridad avanzadas.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.core.exceptions import ValidationError
from django.db import transaction

from .forms import (
    LoginForm, RegistrationForm, ProfileForm,
    PasswordChangeForm, CustomPasswordResetForm
)
from .models import UserProfile, FailedLoginAttempt, SecurityLog
from .utils import (
    check_lockout, record_failed_attempt, clear_failed_attempts,
    is_account_locked, generate_mfa_secret, verify_mfa_code,
    log_security_event, send_verification_email
)
from .decorators import rate_limit, require_2fa


@never_cache
@ensure_csrf_cookie
@sensitive_post_parameters()
def login_view(request):
    """
    Vista de inicio de sesión con protección contra bloqueo
    y registro de intentos fallidos.
    """
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)

        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')

            # Verificar si la cuenta está bloqueada
            if is_account_locked(username):
                messages.error(
                    request,
                    'Demasiados intentos fallidos. Por favor, espere unos minutos.'
                )
                return render(request, 'autho_core/login.html', {'form': form})

            user = authenticate(request, username=username, password=password)

            if user is not None:
                # Verificar si el usuario está activo
                if not user.is_active:
                    messages.error(
                        request,
                        'Esta cuenta está desactivada. Contacte al administrador.'
                    )
                    return render(request, 'autho_core/login.html', {'form': form})

                # Verificar si el correo está verificado (opcional)
                if hasattr(user, 'profile') and user.profile and not user.profile.email_verified:
                    messages.warning(
                        request,
                        'Por favor, verifique su correo electrónico antes de continuar.'
                    )
                    return render(request, 'autho_core/login.html', {'form': form})

                # Verificar 2FA si está habilitado
                if hasattr(user, 'profile') and user.profile and user.profile.mfa_enabled:
                    # Guardar temporalmente el usuario para verificación 2FA
                    request.session['mfa_user_id'] = user.id
                    return redirect('autho_core:mfa_verify')

                # Limpiar intentos fallidos y hacer login
                clear_failed_attempts(username)
                login(request, form.get_user())
                log_security_event(user, 'LOGIN_SUCCESS', request)

                next_url = request.GET.get('next', '')
                if next_url:
                    return redirect(next_url)
                return redirect('autho_core:profile')
            else:
                # Registrar intento fallido
                record_failed_attempt(username)
                log_security_event(None, 'LOGIN_FAILED', request, {'username': username})
                messages.error(request, 'Usuario o contraseña incorrectos.')
        else:
            messages.error(request, 'Por favor, corrija los errores del formulario.')
    else:
        form = LoginForm()

    return render(request, 'autho_core/login.html', {'form': form})


@login_required
def logout_view(request):
    """
    Vista de cierre de sesión con registro de seguridad.
    """
    log_security_event(request.user, 'LOGOUT', request)
    logout(request)
    messages.success(request, 'Ha cerrado sesión correctamente.')
    return redirect('autho_core:login')


@never_cache
@sensitive_post_parameters()
def register_view(request):
    """
    Vista de registro de nuevos usuarios con validaciones de seguridad.
    """
    if request.method == 'POST':
        form = RegistrationForm(request.POST)

        if form.is_valid():
            try:
                with transaction.atomic():
                    user = form.save()

                    # Crear perfil de usuario
                    UserProfile.objects.create(
                        user=user,
                        email_verified=False  # Requiere verificación por correo
                    )

                    # Enviar correo de verificación
                    send_verification_email(user, request)

                    log_security_event(user, 'REGISTRATION', request)

                    messages.success(
                        request,
                        '¡Registro exitoso! Por favor, verifique su correo electrónico.'
                    )
                    return redirect('autho_core:register_success')

            except Exception as e:
                messages.error(request, f'Error al registrar usuario: {str(e)}')
        else:
            messages.error(request, 'Por favor, corrija los errores del formulario.')
    else:
        form = RegistrationForm()

    return render(request, 'autho_core/register.html', {'form': form})


@login_required
def profile_view(request):
    """
    Vista del perfil de usuario con información de seguridad.
    """
    try:
        profile = request.user.profile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=request.user)

    context = {
        'user': request.user,
        'profile': profile,
        'security_events': SecurityLog.objects.filter(
            user=request.user
        ).order_by('-timestamp')[:10]
    }

    return render(request, 'autho_core/profile.html', context)


@login_required
def profile_edit_view(request):
    """
    Vista para editar el perfil de usuario.
    """
    try:
        profile = request.user.profile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=request.user)

    if request.method == 'POST':
        user_form = ProfileForm(request.POST, instance=request.user)

        if user_form.is_valid():
            user_form.save()
            log_security_event(request.user, 'PROFILE_UPDATE', request)
            messages.success(request, 'Perfil actualizado correctamente.')
            return redirect('autho_core:profile')
        else:
            messages.error(request, 'Por favor, corrija los errores del formulario.')
    else:
        user_form = ProfileForm(instance=request.user)

    context = {
        'user_form': user_form,
        'profile': profile
    }

    return render(request, 'autho_core/profile_edit.html', context)


@login_required
@sensitive_post_parameters()
def password_change_view(request):
    """
    Vista para cambiar la contraseña del usuario actual.
    """
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)

        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)
            log_security_event(request.user, 'PASSWORD_CHANGE', request)
            messages.success(request, 'Contraseña cambiada correctamente.')
            return redirect('autho_core:password_change_done')
        else:
            messages.error(request, 'Por favor, corrija los errores del formulario.')
    else:
        form = PasswordChangeForm(request.user)

    return render(request, 'autho_core/password_change.html', {'form': form})


def password_reset_view(request):
    """
    Vista para iniciar el proceso de recuperación de contraseña.
    """
    if request.method == 'POST':
        form = CustomPasswordResetForm(request.POST)

        if form.is_valid():
            try:
                form.save(
                    request=request,
                    use_https=request.is_secure(),
                    email_template_name='autho_core/password_reset_email.html',
                    subject_template_name='autho_core/password_reset_subject.txt'
                )
                messages.success(
                    request,
                    'Se ha enviado un correo con instrucciones para restablecer su contraseña.'
                )
                return redirect('autho_core:password_reset_done')
            except Exception as e:
                messages.error(request, f'Error al enviar el correo: {str(e)}')
        else:
            messages.error(request, 'Por favor, introduzca una dirección de correo válida.')
    else:
        form = CustomPasswordResetForm()

    return render(request, 'autho_core/password_reset.html', {'form': form})


def password_reset_confirm_view(request, uidb64, token):
    """
    Vista para confirmar y completar el restablecimiento de contraseña.
    """
    return PasswordResetConfirmView.as_view(
        template_name='autho_core/password_reset_confirm.html',
        success_url='/password/reset/complete/'
    )(request, uidb64=uidb64, token=token)


def lockout_view(request, credentials=None, *args, **kwargs):
    """
    Vista mostrada cuando un usuario es bloqueado por demasiados intentos fallidos.
    """
    return render(request, 'autho_core/lockout.html', status=429)


def verify_email_view(request, uidb64, token):
    """
    Vista para verificar el correo electrónico del usuario.
    """
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)

        if default_token_generator.check_token(user, token):
            try:
                profile = user.profile
                profile.email_verified = True
                profile.save()

                log_security_event(user, 'EMAIL_VERIFIED', request)

                messages.success(request, '¡Correo verificado correctamente!')
                return redirect('autho_core:login')
            except UserProfile.DoesNotExist:
                messages.error(request, 'Error al verificar el correo.')
                return redirect('autho_core:login')
        else:
            messages.error(request, 'El enlace de verificación es inválido o ha expirado.')
            return redirect('autho_core:login')

    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        messages.error(request, 'El enlace de verificación es inválido.')
        return redirect('autho_core:login')


@login_required
def mfa_setup_view(request):
    """
    Vista para configurar la autenticación de dos factores.
    """
    try:
        profile = request.user.profile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=request.user)

    if request.method == 'POST':
        code = request.POST.get('code')

        if verify_mfa_code(profile.mfa_secret, code):
            profile.mfa_enabled = True
            profile.save()

            log_security_event(request.user, 'MFA_ENABLED', request)
            messages.success(request, '2FA configurado correctamente.')
            return redirect('autho_core:profile')
        else:
            messages.error(request, 'Código inválido. Por favor, inténtelo de nuevo.')

    # Generar secreto si no existe
    if not profile.mfa_secret:
        profile.mfa_secret = generate_mfa_secret()
        profile.save()

    # Generar código QR
    import pyotp
    import qrcode
    from io import BytesIO
    import base64

    totp = pyotp.TOTP(profile.mfa_secret)
    provisioning_uri = totp.provisioning_uri(
        name=request.user.email,
        issuer_name=request.site.name if hasattr(request, 'site') else 'Autho Core'
    )

    qr = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_code = base64.b64encode(buffered.getvalue()).decode()

    context = {
        'qr_code': qr_code,
        'secret': profile.mfa_secret,
        'profile': profile
    }

    return render(request, 'autho_core/mfa_setup.html', context)


def mfa_verify_view(request):
    """
    Vista para verificar el código 2FA durante el login.
    """
    user_id = request.session.get('mfa_user_id')

    if not user_id:
        return redirect('autho_core:login')

    try:
        user = User.objects.get(id=user_id)
        profile = user.profile
    except (User.DoesNotExist, UserProfile.DoesNotExist):
        return redirect('autho_core:login')

    if request.method == 'POST':
        code = request.POST.get('code')

        if verify_mfa_code(profile.mfa_secret, code):
            # Verificación exitosa
            login(request, user)
            del request.session['mfa_user_id']

            log_security_event(user, 'MFA_VERIFIED', request)
            messages.success(request, '¡Bienvenido de nuevo!')
            return redirect('autho_core:profile')
        else:
            messages.error(request, 'Código inválido. Por favor, inténtelo de nuevo.')

    return render(request, 'autho_core/mfa_verify.html', {'user': user})


@login_required
def mfa_disable_view(request):
    """
    Vista para deshabilitar la autenticación de dos factores.
    """
    if request.method == 'POST':
        code = request.POST.get('code')

        try:
            profile = request.user.profile

            if verify_mfa_code(profile.mfa_secret, code):
                profile.mfa_enabled = False
                profile.mfa_secret = None
                profile.save()

                log_security_event(request.user, 'MFA_DISABLED', request)
                messages.success(request, '2FA deshabilitado correctamente.')
                return redirect('autho_core:profile')
            else:
                messages.error(request, 'Código inválido.')
        except UserProfile.DoesNotExist:
            messages.error(request, 'Error al deshabilitar 2FA.')

    return render(request, 'autho_core/mfa_disable.html')


@require_POST
@login_required
def generate_backup_codes_view(request):
    """
    Vista para generar códigos de respaldo para 2FA.
    """
    try:
        profile = request.user.profile

        if not profile.mfa_enabled:
            return JsonResponse({'error': '2FA no está habilitado'}, status=400)

        # Generar códigos de respaldo
        import secrets
        import string

        codes = []
        for _ in range(10):
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            code = f"{code[:4]}-{code[4:]}"
            codes.append(code)

        # Aquí deberías guardar los códigos en la base de datos de forma segura
        # (esto es solo un ejemplo)

        log_security_event(request.user, 'BACKUP_CODES_GENERATED', request)

        return JsonResponse({
            'success': True,
            'codes': codes
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def security_history_view(request):
    """
    Vista para ver el historial de seguridad del usuario.
    """
    events = SecurityLog.objects.filter(
        user=request.user
    ).order_by('-timestamp')[:50]

    context = {
        'events': events,
        'total_events': events.count()
    }

    return render(request, 'autho_core/security_history.html', context)