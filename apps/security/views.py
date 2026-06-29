from django.http import HttpResponse

def lockout_view(request, credentials=None, *args, **kwargs):
    return HttpResponse(
        " Too many failed login attempts. Please try again later.",
        status=429
    )