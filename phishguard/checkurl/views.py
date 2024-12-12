from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required


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
            login(request, user)  # Automatically log the user in
            return redirect('userdash')  # After login, redirect to user dashboard
    else:
        form = UserCreationForm()
    return render(request, 'phishguard/register.html', {'form': form})# User dashboard, user has to be logged in
@login_required
def userdash(request):
    return render(request, 'phishguard/userdash.html')
