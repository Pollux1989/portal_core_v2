from django.shortcuts import render, redirect

from django.contrib.auth import (
    login,
    logout
)

from .forms import (
    LoginForm,
    RegisterForm
)


def login_view(request):

    if request.user.is_authenticated:
        return redirect("dashboard_home")

    form = LoginForm(request, data=request.POST or None)

    if request.method == "POST":

        if form.is_valid():

            user = form.get_user()

            login(request, user)

            return redirect("dashboard_home")

    return render(
        request,
        "accounts/login.html",
        {"form": form}
    )


def register_view(request):

    form = RegisterForm(
        request.POST or None
    )

    if request.method == "POST":

        if form.is_valid():

            user = form.save(commit=False)

            user.email = user.email.strip().lower()

            user.set_password(
                form.cleaned_data["password"]
            )

            user.save()

            login(request, user)

            return redirect("dashboard_home")

    return render(
        request,
        "accounts/register.html",
        {"form": form}
    )


def logout_view(request):

    logout(request)

    return redirect("login")