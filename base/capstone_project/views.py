from django.shortcuts import render
from django.shortcuts import loader
from django.http import HttpResponse
from django.http import HttpResponseRedirect

def capstone_project(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('message')
        print(f"Form submitted: Name={name}, Email={email}, Message={message}")
        return HttpResponseRedirect('/')
    return render(request, 'homepage.html')

def mission_vision(request):
    return render(request, 'mission_vision.html')

def faith_action(request):
    return render(request, 'faith-action.html')

def councils(request):
    return render(request, 'councils.html')

def donations(request):
    if request.method == 'POST':
        amount = request.POST.get('amount')
        name = request.POST.get('name')
        email = request.POST.get('email')
        print(f"Donation Form Submitted: Amount=${amount}, Name={name}, Email={email}")
        return HttpResponseRedirect('/donations/')
    return render(request, 'donations.html')

def sign_in(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        print(f"Sign In Attempt: Username={username}, Password={password}")
        return HttpResponseRedirect('/sign-in/')
    return render(request, 'sign-in.html')

def sign_up(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        print(f"Sign In Attempt: Username={username}, Password={password}")
        return HttpResponseRedirect('/log-in/')
    return render(request, 'sign-up.html')

def about_us(request):
    return render(request, 'about_us.html')

# def capstone_project(request):
#     template = loader.get_template('landing-page.html')
#     return HttpResponse(template.render({}, request))
    # template = loader.get_template('landing-page.html')
    # return HttpResponse(template.render())
    # return render(request, 'index.html')
