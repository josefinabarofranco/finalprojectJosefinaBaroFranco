from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .api import check_url_with_virustotal
from django.conf import settings
import requests

# Home page
def home(request):
    result = None
    if request.method == "POST":
        url = request.POST.get("url")
        if url:
            result = check_url_with_virustotal(url)
    return render(request, 'phishguard/home.html', {'result': result})

# Awareness page (phishing tips)
def awareness(request):
    return render(request, 'phishguard/awareness.html')

# Registration page
def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, 'Your account has been created!')
            return redirect('userdash')
        else:
            messages.error(request, 'Could not register user.')
    else:
        form = UserCreationForm()
    return render(request, 'phishguard/register.html', {'form': form})
@login_required
def userdash(request):
    return render(request, 'phishguard/userdash.html')
