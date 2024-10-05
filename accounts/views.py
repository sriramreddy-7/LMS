from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login 
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
# Create your views here.

def index(request):
    return render(request,"index.html")


def user_login(request):
    if request.method == "POST":
        username = request.POST.get("email")
        password = request.POST.get("password")
        print(username, password)
        user = authenticate(request, username=username, password=password)
        print(user)
        if user is not None:
            login(request, user)
            return HttpResponse("User logged in successfully.") 
        else:
            return HttpResponse(f"{user} Invalid email or password.") 
            # messages.error(request, "Invalid email or password.")
            # return render(request, "login.html")
            
    return render(request, "login.html")

def user_logout(request):
    return HttpResponse("User logged out successfully.")

def user_signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        
        if password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return redirect('signup')
      
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists!")
            return redirect('signup')
        # Check if email is already registered
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered!")
            return redirect('signup')
        # Create a new user
        user = User.objects.create(
            username=username,
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=make_password(password)
        )

        messages.success(request, "Your account has been created successfully! You can now log in.")
        return redirect('login')

    return render(request, 'sign_up.html')

def users_list(request):
    users = User.objects.all()
    return render(request, 'users_list.html', {'users': users})