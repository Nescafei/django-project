from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from django.views.decorators.cache import never_cache
from capstone_project.models import User, Council, Event, Analytics
from django.contrib.sessions.models import Session
import base64
from io import BytesIO
from django.core.files.base import ContentFile
import os
from django.contrib import messages
import re
from datetime import datetime
def capstone_project(request):
    return render(request, 'homepage.html')

def about_us(request):
    return render(request, 'about_us.html')

def events_management(request):
    return render(request, 'events_management.html')

def donation_reports(request):
    return render(request, 'donation_reports.html')

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

@never_cache
def sign_in(request):
    if request.user.is_authenticated:
        print(f"User {request.user.username} already authenticated, redirecting to dashboard")
        return redirect('dashboard')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        print(f"Attempting to authenticate user: {username}")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            if user.is_active and not user.is_archived:
                if user.role == 'pending':
                    pending_message = 'Your account is pending approval. Please wait for an officer to review your request.'
                    print(f"User {username} is pending approval")
                    return render(request, 'sign-in.html', {'pending_message': pending_message})
                else:
                    login(request, user)
                    print(f"User {username} logged in successfully, role: {user.role}, redirecting to dashboard")
                    return redirect('dashboard')
            else:
                print(f"User {username} is not active or is archived")
                return render(request, 'sign-in.html', {'error': 'This account is not active or has been archived'})
        else:
            print(f"Authentication failed for username: {username}")
            return render(request, 'sign-in.html', {'error': 'Invalid username or password'})
    print("Rendering sign-in page")
    return render(request, 'sign-in.html')

@never_cache
def sign_up(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    councils = Council.objects.all()
    print(f"Number of councils available: {councils.count()}")
    if request.method == 'POST':
        full_name = request.POST.get('full_name')
        username = request.POST.get('username')
        email = request.POST.get('email', '')
        password = request.POST.get('password')
        re_password = request.POST.get('re_password')
        birthday = request.POST.get('birthday')
        address = request.POST.get('address')
        contact_number = request.POST.get('contact_number')
        council_id = request.POST.get('council', '')
        print(f"Received form data: full_name={full_name}, username={username}, email={email}, council_id={council_id}, birthday={birthday}, address={address}, contact_number={contact_number}")
        
        if password != re_password:
            print("Validation failed: Passwords do not match")
            return render(request, 'sign-up.html', {'error': 'Passwords do not match', 'councils': councils})

        if not username:
            print("Validation failed: Username is required")
            return render(request, 'sign-up.html', {'error': 'Username is required', 'councils': councils})

        if User.objects.filter(username=username, is_archived=False).exists():
            print(f"Validation failed: Username {username} already exists")
            return render(request, 'sign-up.html', {'error': 'This username is already taken', 'councils': councils})

        # Calculate age from birthday
        try:
            birth_date = datetime.strptime(birthday, '%Y-%m-%d').date()
            today = datetime.today().date()
            age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
            if age < 18:
                print("Validation failed: User must be at least 18 years old")
                return render(request, 'sign-up.html', {'error': 'You must be at least 18 years old to sign up', 'councils': councils})
        except ValueError:
            print("Validation failed: Invalid birthday format")
            return render(request, 'sign-up.html', {'error': 'Invalid birthday format', 'councils': councils})

        try:
            council = Council.objects.get(id=council_id) if council_id else None
            if not council and council_id:
                print("Validation failed: Invalid council selected")
                return render(request, 'sign-up.html', {'error': 'Invalid council selected', 'councils': councils})
        except Council.DoesNotExist:
            print("Validation failed: Council does not exist")
            return render(request, 'sign-up.html', {'error': 'Invalid council selected', 'councils': councils})

        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                role='pending',
                council=council,
                age=age,
                address=address,
                contact_number=contact_number
            )
            user.first_name, user.last_name = full_name.split(' ', 1) if ' ' in full_name else (full_name, '')
            user.save()
            print(f"User {username} saved successfully with details: email={email}, role={user.role}, council={council}, age={age}, address={address}, contact_number={contact_number}")
            success_message = 'Account request submitted. Awaiting approval. Use your username to sign in once approved.'
            return render(request, 'sign-up.html', {'success': success_message, 'councils': councils})
        except Exception as e:
            print(f"Sign Up Error: {str(e)}")
            return render(request, 'sign-up.html', {'error': f'An error occurred during registration: {str(e)}', 'councils': councils})
    return render(request, 'sign-up.html', {'councils': councils})

def logout_view(request):
    logout(request)
    print("User logged out")
    response = redirect('sign-in')
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

@never_cache
@login_required
def dashboard(request):
    if not request.session.session_key or not Session.objects.filter(session_key=request.session.session_key).exists():
        from django.contrib.auth import logout
        logout(request)
        return redirect('sign-in')

    user = request.user
    if user.role == 'pending':
        print(f"User {user.username} is pending, redirecting to sign-in")
        return render(request, 'sign-in.html', {'pending_message': 'Your account is pending approval. Please wait for an officer to review your request.'})

    context = {'user': user}
    if user.role == 'admin':
        user_list = User.objects.filter(is_archived=False)
        events = Event.objects.all()
        analytics = Analytics.objects.all()
        context.update({'user_list': user_list, 'events': events, 'analytics': analytics})
        return render(request, 'admin_dashboard.html', context)
    elif user.role == 'officer':
        if not user.council:
            return redirect('dashboard')  # Redirect if no council assigned
        user_list = User.objects.filter(council=user.council, is_archived=False)
        events = Event.objects.filter(council=user.council)
        analytics = Analytics.objects.filter(council=user.council)
        context.update({'user_list': user_list, 'events': events, 'analytics': analytics})
        return render(request, 'officer_dashboard.html', context)
    elif user.role == 'member':
        if not user.council:
            return redirect('dashboard')
        events = Event.objects.filter(council=user.council)
        context.update({'events': events})
        return render(request, 'member_dashboard.html', context)
    else:
        logout(request)
        return redirect('sign-in')

@never_cache
@login_required
def manage_pending_users(request):
    if request.user.role not in ['officer', 'admin']:
        return redirect('dashboard')
    if request.user.role == 'officer' and request.user.council:
        pending_users = User.objects.filter(role='pending', council=request.user.council, is_archived=False).exclude(role='admin')
    elif request.user.role == 'admin':
        pending_users = User.objects.filter(role='pending', is_archived=False).exclude(role='admin')
    else:
        pending_users = []
    return render(request, 'manage_pending_users.html', {'pending_users': pending_users})

# @never_cache
# @login_required
# def dashboard(request):
#     user = request.user
#     print(f"Dashboard accessed by user: {user.username}, role: {user.role}")
#     if user.role == 'admin':
#         user_list = User.objects.filter(is_archived=False)
#         template = 'admin_dashboard.html'
#         context = {'user': user, 'user_list': user_list}
#     elif user.role == 'officer':
#         template = 'officer_dashboard.html'
#         context = {'user': user}
#     elif user.role == 'member':
#         template = 'member_dashboard.html'
#         context = {'user': user}
#     else:
#         print(f"User {user.username} has invalid role: {user.role}, logging out")
#         logout(request)
#         response = redirect('sign_in')
#         response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
#         response['Pragma'] = 'no-cache'
#         response['Expires'] = '0'
#         return response
#     print(f"Rendering dashboard template: {template}")
#     return render(request, template, context)

# @never_cache
# @login_required
# def manage_pending_users(request):
#     if request.user.role not in ['officer', 'admin']:
#         return redirect('dashboard')
#     council = request.user.council
#     pending_users = User.objects.filter(role='pending', council=council, is_archived=False).exclude(role='admin')
#     print(f"Officer {request.user.username} (Council: {council}) found {len(pending_users)} pending users")
#     return render(request, 'manage_pending_users.html', {'pending_users': pending_users})

@never_cache
@login_required
def approve_user(request, user_id):
    if request.user.role not in ['officer', 'admin']:
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id, is_archived=False)
    if user.council == request.user.council or request.user.role == 'admin':
        user.role = 'member'
        user.save()
        print(f"User {user.username} approved by {request.user.username}")
    return redirect('manage_pending_users')

@never_cache
@login_required
def reject_user(request, user_id):
    if request.user.role not in ['officer', 'admin']:
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id, is_archived=False)
    if user.council == request.user.council or request.user.role == 'admin':
        user.is_active = False
        user.is_archived = True
        user.save()
        print(f"User {user.username} archived by {request.user.username}")
    return redirect('manage_pending_users')

@never_cache
@login_required
def promote_user(request, user_id):
    if request.user.role != 'admin':
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id, is_archived=False)
    user.role = 'officer'
    user.save()
    return redirect('dashboard')

@never_cache
@login_required
def demote_user(request, user_id):
    if request.user.role != 'admin':
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id, is_archived=False)
    user.role = 'member'
    user.save()
    return redirect('dashboard')

@never_cache
@login_required
def archive_user(request, user_id):
    if request.user.role != 'admin':
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id, is_archived=False)
    if user == request.user:
        print(f"User {request.user.username} attempted to archive themselves")
        return redirect('dashboard')
    user.is_active = False
    user.is_archived = True
    user.save()
    print(f"User {user.username} archived by {request.user.username}")
    return redirect('dashboard')

@never_cache
@login_required
def archived_users(request):
    if request.user.role != 'admin':
        return redirect('dashboard')
    archived_users = User.objects.filter(is_archived=True)
    print(f"Admin {request.user.username} accessed archived users: {archived_users.count()} found")
    return render(request, 'archived_users.html', {'archived_users': archived_users})

@never_cache
@login_required
def analytics_form(request):
    if request.user.role != 'officer':
        return redirect('dashboard')
    council = request.user.council
    if request.method == 'POST':
        events_count = int(request.POST.get('events_count', 0))
        donations_amount = float(request.POST.get('donations_amount', 0.00))
        analytics, created = Analytics.objects.get_or_create(council=council)
        analytics.events_count = events_count
        analytics.donations_amount = donations_amount
        analytics.updated_by = request.user
        analytics.save()
        return redirect('dashboard')
    analytics = Analytics.objects.filter(council=council).first()
    return render(request, 'analytics_form.html', {'analytics': analytics})

@never_cache
@login_required
def analytics_view(request):
    if request.user.role != 'admin':
        return redirect('dashboard')
    analytics = Analytics.objects.all()
    return render(request, 'analytics_view.html', {'analytics': analytics})

@never_cache
@login_required
def update_degree(request, user_id):
    if request.user.role not in ['officer', 'admin']:
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id, is_archived=False)
    # Allow admin to modify any user, officer can only modify members in their council
    if request.user.role == 'officer' and (user.role != 'member' or user.council != request.user.council):
        return redirect('dashboard')
    if request.method == 'POST':
        degree = request.POST.get('current_degree')
        print(f"Received degree: {degree}")
        valid_degrees = [choice[0] for choice in User._meta.get_field('current_degree').choices]
        print(f"Valid degrees: {valid_degrees}")
        if degree in valid_degrees:
            user.current_degree = degree
            user.save()
            print(f"User {user.username}'s degree updated to {degree} by {request.user.username}")
        else:
            print(f"Invalid degree {degree} selected for user {user.username}")
        return redirect('dashboard')
    return render(request, 'update_degree.html', {'user': user})

@never_cache
@login_required
def edit_profile(request):
    user = request.user
    if request.method == 'POST':
        try:
            # Update user fields
            user.first_name = request.POST.get('first_name', user.first_name)
            user.last_name = request.POST.get('last_name', user.last_name)
            user.username = request.POST.get('username', user.username)
            user.address = request.POST.get('address', user.address)
            user.contact_number = request.POST.get('contact_number', user.contact_number)

            # Update password if provided
            password = request.POST.get('password')
            if password:
                user.set_password(password)

            # Handle profile picture
            cropped_image = request.POST.get('cropped_image')
            if cropped_image:
                format, imgstr = re.match(r'data:image/(\w+);base64,(.+)', cropped_image).groups()
                image_data = base64.b64decode(imgstr)
                filename = f'{user.username}_profile.jpg'
                user.profile_picture.save(filename, ContentFile(image_data), save=False)

            user.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f'Error updating profile: {str(e)}')
    
    return render(request, 'edit_profile.html', {'user': user})
@login_required
def search_users(request):
    query = request.GET.get('q')
    results = []
    if query:
        results = User.objects.filter(username__icontains=query, is_archived=False).exclude(role='pending')
    return render(request, 'search_results.html', {'results': results, 'query': query})