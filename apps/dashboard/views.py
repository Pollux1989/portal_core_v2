from django.shortcuts import render

def test_page(request):
    return render(request, "test.html")

def dashboard_home(request):
    return render(request, "dashboard/home.html")
