from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import SavedURL

# Home page
def home(request):
    result = None
    if request.method == "POST":
        url = request.POST.get("url")
        if url:
            if request.user.is_authenticated:
                SavedURL.objects.create(user=request.user, url=url)
            result = check_url_with_virustotal(url)
    return render(request, 'phishguard/home.html', {'result': result})

# Awareness page (phishing tips)
def awareness(request):
    return render(request, 'phishguard/awareness.html')

# Registration page
def register(request):
    if request.method == 'POST':
        if 'register' in request.POST:
            return handle_registration(request)
        elif 'login' in request.POST:
            return handle_login(request)

    else:
        form = UserCreationForm()

    return render(request, 'phishguard/register.html', {'form': form})


def handle_registration(request):
    form = UserCreationForm(request.POST)
    if form.is_valid():
        user = form.save()
        login(request, user)
        messages.success(request, 'Your account has been created successfully!')
        return redirect('userdash')
    else:
        messages.error(request, 'Could not register user. Please try again.')
        return render(request, 'phishguard/register.html', {'form': form})


def handle_login(request):
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)
        return redirect('userdash')
    else:
        messages.error(request, 'Invalid credentials. Please try again.')
        return render(request, 'phishguard/register.html')

@login_required
def userdash(request):
    saved_urls = SavedURL.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'phishguard/userdash.html', {'saved_urls': saved_urls})
