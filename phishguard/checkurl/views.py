from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib import messages

# Home page
def home(request):
    if request.method == 'POST':
        user_url = request.POST.get('url')

        result = check_url_api(user_url)
        return render(request, 'phishguard/home.html', {'result': result})
    return render(request, 'phishguard/home.html')

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
