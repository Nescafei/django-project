from .models import User, Council, Event, Analytics, Donation, Blockchain, blockchain, Block, ForumCategory, ForumMessage, Notification, EventAttendance, Recruitment
from django.contrib.auth.decorators import login_required, permission_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseRedirect, JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.contrib.sessions.models import Session
from django.template.loader import render_to_string
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.paginator import Paginator
from .forms import DonationForm, ManualDonationForm
from django.contrib import messages
from django.db import transaction
from django.db.models.signals import pre_save, pre_delete
from django.db.models import Count, Sum, Avg, Q
from django.dispatch import receiver
from django.conf import settings
from django.urls import reverse
from io import BytesIO
from datetime import datetime, date, timezone, timedelta
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
PRIVATE_KEY = getattr(settings, 'PRIVATE_KEY', None)
PUBLIC_KEY = getattr(settings, 'PUBLIC_KEY', None)
import base64
import pandas as pd
import os
import re
import uuid
import logging
import requests
import json
from django.db.models import Q
from django.core.mail import send_mail

def load_keys():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(base_dir, 'private_key.pem'), 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(os.path.join(base_dir, 'public_key.pem'), 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return private_key, public_key

PRIVATE_KEY, PUBLIC_KEY = load_keys()

logger = logging.getLogger(__name__)
@receiver(pre_save, sender=Block)
def log_block_change(sender, instance, **kwargs):
    if instance.pk:
        old_block = Block.objects.get(pk=instance.pk)
        logger.warning(f"Block {instance.index} modified: Old={old_block.__dict__}, New={instance.__dict__}")

@receiver(pre_delete, sender=Block)
def log_block_delete(sender, instance, **kwargs):
    timestamp_str = instance.timestamp.isoformat() if isinstance(instance.timestamp, datetime) else str(instance.timestamp)
    logger.warning(f"Block {instance.index} deleted: index={instance.index}, timestamp={timestamp_str}")

PAYMONGO_API_URL = 'https://api.paymongo.com/v1'

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
    councils = Council.objects.all()
    return render(request, 'councils.html', {'councils': councils})

def council_detail(request, council_id):
    try:
        council = Council.objects.get(id=council_id)
        
        # Get admin, officers, and members for this council
        admin = User.objects.filter(council=council, role='admin', is_archived=False).first()
        officers = User.objects.filter(council=council, role='officer', is_archived=False).order_by('first_name')
        members = User.objects.filter(council=council, role='member', is_archived=False).order_by('first_name')
        
        context = {
            'council': council,
            'admin': admin,
            'officers': officers,
            'members': members
        }
        
        return render(request, 'council_detail.html', context)
    except Council.DoesNotExist:
        # Handle case where council doesn't exist
        return redirect('councils')

def donation_page(request):
    if request.method == 'POST':
        return render(request, 'donation_form.html', {
            'error': 'Form submission failed. Please try again.'
        })
    return render(request, 'donation_form.html')

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
                    messages.warning(request, 'Your account is pending approval. Please wait for an officer to review your request.')
                    print(f"User {username} is pending approval")
                    return render(request, 'sign-in.html')
                else:
                    login(request, user)
                    # Set session to expire according to settings (8 hours)
                    request.session.set_expiry(settings.SESSION_COOKIE_AGE)
                    # Initialize last_activity timestamp
                    request.session['last_activity'] = datetime.now().timestamp()
                    request.session.modified = True
                    print(f"User {username} logged in successfully, role: {user.role}, redirecting to dashboard")
                    return redirect('dashboard')
            else:
                print(f"User {username} is not active or is archived")
                messages.error(request, 'This account is not active or has been archived')
                return render(request, 'sign-in.html')
        else:
            print(f"Authentication failed for username: {username}")
            messages.error(request, 'Invalid username or password')
            return render(request, 'sign-in.html')
    print("Rendering sign-in page")
    return render(request, 'sign-in.html')


@never_cache
def sign_up(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    councils = Council.objects.all()
    print(f"Number of councils available: {councils.count()}")
    if request.method == 'POST':
        # Debug information for file uploads
        print(f"POST data: {request.POST}")
        print(f"FILES data: {request.FILES}")
        if 'e_signature' in request.FILES:
            e_signature_file = request.FILES['e_signature']
            print(f"E-signature file received: {e_signature_file.name}, size: {e_signature_file.size}, type: {e_signature_file.content_type}")
        else:
            print("No e-signature file received in request.FILES")
            
        first_name = request.POST.get('first_name')
        second_name = request.POST.get('second_name', '')  # Optional
        middle_name = request.POST.get('middle_name')
        last_name = request.POST.get('last_name')
        suffix = request.POST.get('suffix', '')  # Optional
        username = request.POST.get('username')
        email = request.POST.get('email', '')
        password = request.POST.get('password')
        re_password = request.POST.get('re_password')
        birthday = request.POST.get('birthday')
        street = request.POST.get('street')
        barangay = request.POST.get('barangay')
        city = request.POST.get('city')
        province = request.POST.get('province')
        zip_code = request.POST.get('zip_code')
        contact_number = request.POST.get('contact_number')
        council_id = request.POST.get('council', '')
        # New fields
        practical_catholic = request.POST.get('practical_catholic')
        marital_status = request.POST.get('marital_status')
        occupation = request.POST.get('occupation')
        recruiter_name = request.POST.get('recruiter_name', '')
        voluntary_join = request.POST.get('voluntary_join') == 'on'
        privacy_agreement = request.POST.get('privacy_agreement')
        e_signature = request.FILES.get('e_signature')
        join_reason = request.POST.get('join_reason', '')
        
        # Set default values for gender and religion
        gender = 'Male'  # Default to Male for Knights of Columbus
        religion = 'Catholic'  # Default to Catholic for Knights of Columbus
        
        print(f"Received form data: first_name={first_name}, second_name={second_name}, middle_name={middle_name}, last_name={last_name}, suffix={suffix}, username={username}, email={email}, council_id={council_id}, birthday={birthday}, street={street}, barangay={barangay}, city={city}, province={province}, contact_number={contact_number}, practical_catholic={practical_catholic}, marital_status={marital_status}, occupation={occupation}, recruiter_name={recruiter_name}, voluntary_join={voluntary_join}, privacy_agreement={privacy_agreement}, e_signature={e_signature.name if e_signature else None}, join_reason={join_reason}")

        if password != re_password:
            print("Validation failed: Passwords do not match")
            messages.error(request, 'Passwords do not match')
            return render(request, 'sign-up.html', {'councils': councils})

        if not username:
            print("Validation failed: Username is required")
            messages.error(request, 'Username is required')
            return render(request, 'sign-up.html', {'councils': councils})

        if User.objects.filter(username=username, is_archived=False).exists():
            print(f"Validation failed: Username {username} already exists")
            messages.error(request, 'This username is already taken')
            return render(request, 'sign-up.html', {'councils': councils})

        # Check if email already exists
        if email and User.objects.filter(email=email, is_archived=False).exists():
            print(f"Validation failed: Email {email} already exists")
            messages.error(request, 'This email address is already registered')
            return render(request, 'sign-up.html', {'councils': councils})

        # Calculate age from birthday
        birth_date = None
        age = None
        if birthday:
            try:
                birth_date = datetime.strptime(birthday, '%Y-%m-%d').date()
                today = datetime.today().date()
                age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
                if age < 18:
                    print("Validation failed: User must be at least 18 years old")
                    messages.error(request, 'You must be at least 18 years old to sign up')
                    return render(request, 'sign-up.html', {'councils': councils})
            except ValueError as e:
                print(f"Validation failed: Invalid birthday format - {str(e)}")
                messages.error(request, 'Invalid birthday format. Use YYYY-MM-DD.')
                return render(request, 'sign-up.html', {'councils': councils})
        else:
            print("Validation failed: Birthday is required")
            messages.error(request, 'Birthday is required')
            return render(request, 'sign-up.html', {'councils': councils})

        # Validate practical Catholic
        if practical_catholic != 'Yes':
            print("Validation failed: User must be a practical Catholic")
            messages.error(request, 'You must be a practical Catholic to join Knights of Columbus')
            return render(request, 'sign-up.html', {'councils': councils})

        # Validate privacy agreement
        if privacy_agreement != 'agree':
            print("Validation failed: User must agree to the privacy policy")
            messages.error(request, 'You must agree to the data privacy agreement to create an account')
            return render(request, 'sign-up.html', {'councils': councils})

        # Validate e-signature
        if not e_signature:
            print("Validation failed: E-signature is required")
            messages.error(request, 'Please upload your e-signature')
            return render(request, 'sign-up.html', {'councils': councils})
        
        # Check e-signature file size (10MB limit)
        if e_signature.size > 10 * 1024 * 1024:  # 10MB in bytes
            print(f"Validation failed: E-signature file size exceeds 10MB limit. Size: {e_signature.size} bytes")
            messages.error(request, 'E-signature file size exceeds 10MB limit')
            return render(request, 'sign-up.html', {'councils': councils})
        
        # Check e-signature file type
        allowed_types = ['image/jpeg', 'image/png', 'image/gif']
        if hasattr(e_signature, 'content_type') and e_signature.content_type not in allowed_types:
            print(f"Validation failed: Invalid e-signature file type: {e_signature.content_type}")
            messages.error(request, f'E-signature must be a JPG, PNG, or GIF image. Detected: {e_signature.content_type}')
            return render(request, 'sign-up.html', {'councils': councils})

        try:
            council = Council.objects.get(id=council_id) if council_id else None
            if not council and council_id:
                print("Validation failed: Invalid council selected")
                messages.error(request, 'Invalid council selected')
                return render(request, 'sign-up.html', {'councils': councils})
        except Council.DoesNotExist:
            print("Validation failed: Council does not exist")
            messages.error(request, 'Invalid council selected')
            return render(request, 'sign-up.html', {'councils': councils})

        # Generate middle initial from middle name
        middle_initial = f"{middle_name[0]}." if middle_name else None

        try:
            # Create user without saving e-signature first
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                role='pending',
                council=council,
                age=age,
                first_name=first_name,
                second_name=second_name,
                middle_name=middle_name,
                middle_initial=middle_initial,
                last_name=last_name,
                suffix=suffix,
                street=street,
                barangay=barangay,
                city=city,
                province=province,
                zip_code=zip_code,
                contact_number=contact_number,
                birthday=birth_date,
                gender=gender,
                religion=religion,
                # Save new fields
                practical_catholic=practical_catholic == 'Yes',
                marital_status=marital_status,
                occupation=occupation,
                recruiter_name='' if voluntary_join else recruiter_name,
                voluntary_join=voluntary_join,
                join_reason=join_reason
            )
            
            # Save e-signature in a separate step
            if e_signature:
                try:
                    user.e_signature = e_signature
                    user.save()
                    print(f"E-signature saved successfully for user {username}")
                except Exception as e:
                    print(f"Error saving e-signature: {str(e)}")
                    # Continue with registration even if e-signature fails
            
            print(f"User {username} saved successfully with details: email={email}, role={user.role}, council={council}, age={age}, birthday={user.birthday}, first_name={first_name}, second_name={second_name}, middle_name={middle_name}, middle_initial={middle_initial}, last_name={last_name}, suffix={suffix}, street={street}, barangay={barangay}, city={city}, province={province}, zip_code={zip_code}, contact_number={contact_number}, gender={gender}, religion={religion}, practical_catholic={practical_catholic}, marital_status={marital_status}, occupation={occupation}, recruiter_name={recruiter_name}, voluntary_join={voluntary_join}, join_reason={join_reason}")
            messages.success(request, 'Account request submitted. Awaiting approval. Use your username to sign in once approved.')
            return render(request, 'sign-up.html', {'councils': councils})
        except Exception as e:
            print(f"Error creating user: {str(e)}")
            messages.error(request, f'An error occurred during registration: {str(e)}')
            return render(request, 'sign-up.html', {'councils': councils})
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
    from datetime import date
    today = date.today()
    
    # Session refresh - update the session expiry time on each request
    request.session.set_expiry(settings.SESSION_COOKIE_AGE)
    request.session.modified = True
    
    user = request.user
    if user.role == 'pending':
        print(f"User {user.username} is pending, redirecting to sign-in")
        return render(request, 'sign-in.html', {'pending_message': 'Your account is pending approval. Please wait for an officer to review your request.'})
    
    if user.role == 'admin':
        return admin_dashboard(request)
    elif user.role == 'officer':
        return officer_dashboard(request)
    elif user.role == 'member':
        return member_dashboard(request)
    else:
        logout(request)
        return redirect('sign-in')

def admin_dashboard(request):
    """Dashboard view for admins"""
    from datetime import date
    today = date.today()
    
    user = request.user
    user_list = User.objects.filter(is_archived=False)
    
    # Only show approved upcoming events (not pending or rejected)
    events = Event.objects.filter(
        date_from__gte=today,
        status='approved'
    )
    
    # Count only approved events
    approved_events_count = Event.objects.filter(status='approved', date_from__gte=today).count()
    analytics = Analytics.objects.all()
    
    context = {
        'user': user,
        'user_list': user_list, 
        'events': events, 
        'approved_events_count': approved_events_count,
        'analytics': analytics
    }
    
    return render(request, 'admin_dashboard.html', context)

def officer_dashboard(request):
    """Dashboard view for officers"""
    from datetime import date
    today = date.today()
    
    user = request.user
    if not user.council:
        return redirect('dashboard')  # Redirect if no council assigned
    
    user_list = User.objects.filter(council=user.council, is_archived=False)
    
    # Officers see their council's current/future events and global events
    # Only show approved and pending events (not rejected)
    events = Event.objects.filter(
        (Q(council=user.council) | Q(is_global=True)) & 
        Q(date_from__gte=today)
    )
    # Count only approved events
    approved_events_count = Event.objects.filter(
        (Q(council=user.council) | Q(is_global=True)) & 
        Q(status='approved', date_from__gte=today)
    ).count()
    analytics = Analytics.objects.filter(council=user.council)
    
    context = {
        'user': user,
        'user_list': user_list, 
        'events': events, 
        'approved_events_count': approved_events_count,
        'analytics': analytics
    }
    
    return render(request, 'officer_dashboard.html', context)

def member_dashboard(request):
    """Dashboard view for members"""
    from datetime import date
    today = date.today()
    
    user = request.user
    if not user.council:
        return redirect('dashboard')
    
    # Members see their council's current/future events and global events
    events = Event.objects.filter(
        (Q(council=user.council) | Q(is_global=True)) &
        Q(date_from__gte=today)
    )
    # Count only approved events
    approved_events_count = Event.objects.filter(
        (Q(council=user.council) | Q(is_global=True)) & 
        Q(status='approved', date_from__gte=today)
    ).count()
    
    # Get activities (events attended)
    activities_count = EventAttendance.objects.filter(member=user, is_present=True).count()
    
    # Get council announcements
    announcements = []
    council_updates = []
    if user.council:
        # TODO: Implement council announcements
        pass
    
    # Get forum messages
    forum_messages = ForumMessage.objects.all().order_by('-timestamp')[:5]
    
    context = {
        'user': user,
        'events': events, 
        'approved_events_count': approved_events_count,
        'activities_count': activities_count,
        'announcements': announcements,
        'forum_messages': forum_messages,
        'council_updates': council_updates,
    }
    
    return render(request, 'member_dashboard.html', context)

def pending_dashboard(request):
    """Dashboard view for pending users"""
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

@never_cache
@login_required
def approve_user(request, user_id):
    if request.user.role not in ['officer', 'admin']:
        return redirect('dashboard')
    
    user = get_object_or_404(User, id=user_id, is_archived=False)
    
    # Get the role from POST data (only admin can assign officer role)
    selected_role = request.POST.get('role', 'member')
    if selected_role == 'officer' and request.user.role != 'admin':
        selected_role = 'member'  # Officers can only approve as members
    
    if user.council == request.user.council or request.user.role == 'admin':
        user.role = selected_role
        # Ensure the user is active
        user.is_active = True
        
        # Set 1st degree for newly approved users
        if not user.current_degree:
            user.current_degree = '1st'
            print(f"User {user.username} assigned 1st degree upon approval")
        
        # Check if this user was recruited by someone
        if user.recruiter_name and not user.voluntary_join:
            try:
                from django.utils import timezone
                
                # Find the recruiter by name - improved matching logic
                recruiter_name = user.recruiter_name.strip()
                print(f"Looking for recruiter with name: {recruiter_name}")
                
                # Try exact match first (in case it's a username)
                recruiters = User.objects.filter(
                    username__iexact=recruiter_name,
                    is_archived=False
                )
                
                # If no match, try by first and last name
                if recruiters.count() == 0 and ' ' in recruiter_name:
                    recruiter_names = recruiter_name.split()
                    
                    # Try different combinations
                    if len(recruiter_names) >= 2:
                        first_name = recruiter_names[0]
                        last_name = recruiter_names[-1]
                        
                        # Try first and last name match
                        recruiters = User.objects.filter(
                            first_name__iexact=first_name,
                            last_name__iexact=last_name,
                            is_archived=False
                        )
                        
                        # If still no match, try partial matches
                        if recruiters.count() == 0:
                            recruiters = User.objects.filter(
                                first_name__icontains=first_name,
                                last_name__icontains=last_name,
                                is_archived=False
                            )
                
                # If we found exactly one recruiter, create the recruitment record
                if recruiters.count() == 1:
                    recruiter = recruiters.first()
                    print(f"Found recruiter: {recruiter.username} ({recruiter.first_name} {recruiter.last_name})")
                    
                    # Check if recruitment record already exists
                    existing_recruitment = Recruitment.objects.filter(
                        recruiter=recruiter,
                        recruited=user
                    ).first()
                    
                    if not existing_recruitment:
                        # Create recruitment record
                        Recruitment.objects.create(
                            recruiter=recruiter,
                            recruited=user,
                            date_recruited=timezone.now().date(),
                            is_manual=False  # This is automatically created, not manually added
                        )
                        print(f"Recruitment record created: {recruiter.username} recruited {user.username}")
                        
                        # Check if recruiter should be promoted to next degree
                        recalculate_degree(recruiter)
                    else:
                        print(f"Recruitment record already exists for {recruiter.username} and {user.username}")
                elif recruiters.count() > 1:
                    print(f"Multiple potential recruiters found for name '{recruiter_name}', skipping recruitment record")
                else:
                    print(f"No recruiter found for name '{recruiter_name}', skipping recruitment record")
            except Exception as e:
                print(f"Error processing recruiter information: {str(e)}")
                import traceback
                traceback.print_exc()
        
        user.save()
        messages.success(request, f'User {user.first_name} {user.last_name} has been approved as {selected_role}.')
        print(f"User {user.username} approved as {selected_role} by {request.user.username}")
    
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
    messages.success(request, f"{user.first_name} {user.last_name} has been promoted to Officer.")
    return redirect('manage_roles')

@never_cache
@login_required
def demote_user(request, user_id):
    if request.user.role != 'admin':
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id, is_archived=False)
    user.role = 'member'
    user.save()
    messages.success(request, f"{user.first_name} {user.last_name} has been demoted to Member.")
    return redirect('manage_roles')


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
def analytics_view(request):
    if request.user.role not in ['admin', 'officer']:
        return redirect('dashboard')
    
    # Admin can select any council, officers are restricted to their own council
    if request.user.role == 'officer':
        council_id = str(request.user.council.id) if request.user.council else None
        councils = Council.objects.filter(id=council_id) if council_id else Council.objects.none()
    else:  # Admin
        council_id = request.GET.get('council_id')
        councils = Council.objects.all()

    # 1. Events Done Data
    events_qs = Event.objects.filter(status='approved')
    if council_id:
        events_qs = events_qs.filter(council_id=council_id)
    events_df = pd.DataFrame(list(events_qs.values('council__name')))
    if events_df.empty:
        council_name = Council.objects.get(id=council_id).name if council_id else 'Global'
        events_data = [{'council_name': council_name, 'count': 0}]
    else:
        events_df = events_df.groupby('council__name').size().reset_index(name='count')
        events_df['council_name'] = events_df['council__name'].fillna('Global')
        events_data = events_df.to_dict('records')
    logger.debug(f"Events data: {events_data}")

    # 2. Donations Per Month Data
    donations_qs = Donation.objects.filter(status='completed')
    if council_id:
        donations_qs = donations_qs.filter(submitted_by__council_id=council_id)
    donations_df = pd.DataFrame(list(donations_qs.values('donation_date', 'amount')))
    if donations_df.empty:
        donations_data = []
    else:
        donations_df['year'] = pd.to_datetime(donations_df['donation_date']).dt.year
        donations_df['month'] = pd.to_datetime(donations_df['donation_date']).dt.strftime('%B')  # Full month name (e.g., "May")
        donations_df = donations_df.groupby(['year', 'month'])['amount'].sum().reset_index()
        donations_df['month'] = donations_df['month']
        donations_data = [{'month': row['month'], 'total': float(row['amount'])} for _, row in donations_df.iterrows()]
    logger.debug(f"Donations data: {donations_data}")

    # 3. Members and Officers Data
    users_qs = User.objects.filter(is_archived=False)
    if council_id:
        users_qs = users_qs.filter(council_id=council_id)
    users_df = pd.DataFrame(list(users_qs.values('council__name', 'role')))
    if users_df.empty:
        council_name = Council.objects.get(id=council_id).name if council_id else 'Global'
        members_officers_data = [{'council_name': council_name, 'members': 0, 'officers': 0}]
    else:
        users_df['council_name'] = users_df['council__name'].fillna('Global')
        members_df = users_df[users_df['role'] == 'member'].groupby('council_name').size().reset_index(name='members')
        officers_df = users_df[users_df['role'] == 'officer'].groupby('council_name').size().reset_index(name='officers')
        merged_df = pd.merge(members_df, officers_df, on='council_name', how='outer').fillna(0)
        members_officers_data = merged_df.to_dict('records')
    logger.debug(f"Members/officers data: {members_officers_data}")

    # 4. Event Type Distribution
    event_types_qs = Event.objects.filter(status='approved')
    if council_id:
        event_types_qs = event_types_qs.filter(council_id=council_id)
    event_types_df = pd.DataFrame(list(event_types_qs.values('category')))
    if event_types_df.empty:
        event_types_data = []
    else:
        event_types_df = event_types_df.groupby('category').size().reset_index(name='count')
        event_types_data = event_types_df.to_dict('records')
    logger.debug(f"Event types data: {event_types_data}")

    # 5. Donation Source Breakdown
    donation_sources_qs = Donation.objects.filter(status='completed')
    if council_id:
        donation_sources_qs = donation_sources_qs.filter(submitted_by__council_id=council_id)
    donation_sources_df = pd.DataFrame(list(donation_sources_qs.values('payment_method', 'amount')))
    if donation_sources_df.empty:
        donation_sources_data = []
    else:
        donation_sources_df = donation_sources_df.groupby('payment_method')['amount'].sum().reset_index()
        donation_sources_data = [{'payment_method': row['payment_method'], 'amount': float(row['amount'])} for _, row in donation_sources_df.iterrows()]
    logger.debug(f"Donation sources data: {donation_sources_data}")

    # 6. Active vs. Inactive Members
    users_qs = User.objects.filter(is_archived=False, role='member')
    if council_id:
        users_qs = users_qs.filter(council_id=council_id)
    total_members = users_qs.count()
    active_members = users_qs.filter(
        Q(submitted_donations__status='completed') |
        Q(event_attendances__is_present=True, event_attendances__event__status='approved')
    ).distinct().count()
    logger.debug(f"Active members: {active_members}, Total members: {total_members}")
    member_activity_data = [
        {'category': 'Active Members', 'count': active_members},
        {'category': 'Inactive Members', 'count': total_members - active_members}
    ]
    logger.debug(f"Member activity data: {member_activity_data}")

    # 7. Summary Statistics
    summary_stats = {
        'total_events': float(Event.objects.filter(status='approved').count() if not council_id else Event.objects.filter(status='approved', council_id=council_id).count()),
        'total_donations': float(Donation.objects.filter(status='completed').aggregate(Sum('amount'))['amount__sum'] or 0) if not council_id else float(Donation.objects.filter(status='completed', submitted_by__council_id=council_id).aggregate(Sum('amount'))['amount__sum'] or 0),
        'total_members': float(User.objects.filter(is_archived=False, role='member').count() if not council_id else User.objects.filter(is_archived=False, role='member', council_id=council_id).count()),
        'total_officers': float(User.objects.filter(is_archived=False, role='officer').count() if not council_id else User.objects.filter(is_archived=False, role='officer', council_id=council_id).count()),
        'avg_donation': float(Donation.objects.filter(status='completed').aggregate(Avg('amount'))['amount__avg'] or 0) if not council_id else float(Donation.objects.filter(status='completed', submitted_by__council_id=council_id).aggregate(Avg('amount'))['amount__avg'] or 0),
    }
    logger.debug(f"Summary stats: {summary_stats}")

    # Convert data to JSON for Chart.js
    context = {
        'councils': councils,
        'selected_council': council_id,
        'events_data': json.dumps(events_data),
        'donations_data': json.dumps(donations_data),
        'members_officers_data': json.dumps(members_officers_data),
        'event_types_data': json.dumps(event_types_data),
        'donation_sources_data': json.dumps(donation_sources_data),
        'member_activity_data': json.dumps(member_activity_data),
        'summary_stats': summary_stats,
        'is_officer': request.user.role == 'officer'
    }
    return render(request, 'analytics_view.html', context)
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
        valid_degrees = [choice[0] for choice in User.DEGREE_CHOICES]
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
            user.second_name = request.POST.get('second_name', user.second_name)
            user.middle_name = request.POST.get('middle_name', user.middle_name)
            # Generate middle_initial from middle_name
            if user.middle_name:
                user.middle_initial = f"{user.middle_name[0]}."
            user.last_name = request.POST.get('last_name', user.last_name)
            user.suffix = request.POST.get('suffix', user.suffix)
            user.username = request.POST.get('username', user.username)
            user.street = request.POST.get('street', user.street)
            user.barangay = request.POST.get('barangay', user.barangay)
            user.city = request.POST.get('city', user.city)
            user.province = request.POST.get('province', user.province)
            user.zip_code = request.POST.get('zip_code', user.zip_code)
            user.contact_number = request.POST.get('contact_number', user.contact_number)
            user.gender = request.POST.get('gender', user.gender)
            user.religion = request.POST.get('religion', user.religion)

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
            # Stay on the same page instead of redirecting
            return render(request, 'edit_profile.html', {'user': user})
        except Exception as e:
            messages.error(request, f'Error updating profile: {str(e)}')
    
    return render(request, 'edit_profile.html', {'user': user})

# @login_required
# def search_users(request):
#     query = request.GET.get('q')
#     results = []
#     if query:
#         results = User.objects.filter(username__icontains=query, is_archived=False).exclude(role='pending')
#     return render(request, 'search_results.html', {'results': results, 'query': query})

@login_required
def forum(request):
    if not request.user.is_authenticated or request.user.role == 'pending':
        return redirect('sign-in')
        
    categories = ForumCategory.objects.all()
    user_council = request.user.council
    context = {
        'categories': categories,
        'current_user': request.user,
        'user_council': user_council,
    }
    return render(request, 'forum/forum.html', context)

@login_required
def get_messages(request, category_id):
    category = get_object_or_404(ForumCategory, id=category_id)
    forum_type = request.GET.get('forum_type', 'council')  # Default to council (public)
    
    # Filter messages based on forum type
    if forum_type == 'district':
        # Private forum - only show messages from user's council
        messages = ForumMessage.objects.filter(
            category=category,
            council=request.user.council,
            is_district_forum=True
        ).select_related('sender', 'council').order_by('timestamp')
    else:
        # Public forum - show messages from all councils
        messages = ForumMessage.objects.filter(
            category=category,
            is_district_forum=False
        ).select_related('sender', 'council').order_by('timestamp')
    
    messages_data = []
    for msg in messages:
        profile_picture_url = msg.sender.profile_picture.url if msg.sender.profile_picture else None
        image_url = msg.image.url if msg.image else None
        
        messages_data.append({
            'id': msg.id,
            'content': msg.content,
            'sender': msg.sender.username,
            'sender_first_name': msg.sender.first_name,
            'sender_last_name': msg.sender.last_name,
            'sender_role': msg.sender.role,
            'council': msg.council.id,
            'timestamp': msg.timestamp.strftime('%m/%d/%y %H:%M'),
            'is_pinned': msg.is_pinned,
            'can_delete': request.user.role == 'admin' or request.user == msg.sender,
            'sender_profile_picture': profile_picture_url,
            'image_url': image_url,
        })
    
    return JsonResponse({'messages': messages_data})

@login_required
@csrf_protect
def send_message(request):
    if request.method == 'POST':
        try:
            category_id = request.POST.get('category_id')
            content = request.POST.get('content', '')
            image = request.FILES.get('image')
            forum_type = request.POST.get('forum_type', 'council')  # Default to council (public)
            
            category = get_object_or_404(ForumCategory, id=category_id)
            
            message = ForumMessage.objects.create(
                sender=request.user,
                category=category,
                content=content,
                council=request.user.council,
                is_district_forum=(forum_type == 'district')  # Set flag based on forum type
            )
            
            # Handle image upload if provided
            if image:
                message.image = image
                message.save()
            
            # Create notifications for other users
            if forum_type == 'district':
                # Only notify users in the same council for district messages
                other_users = User.objects.filter(
                    council=request.user.council
                ).exclude(id=request.user.id)
            else:
                # Notify all users for council messages
                other_users = User.objects.exclude(id=request.user.id)
            
            notifications = [
                Notification(user=user, message=message)
                for user in other_users
            ]
            Notification.objects.bulk_create(notifications)
            
            return JsonResponse({
                'status': 'success',
                'message_id': message.id,
                'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M')
            })
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    
    return JsonResponse({'status': 'error'}, status=400)

@login_required
@csrf_protect
def delete_message(request, message_id):
    message = get_object_or_404(ForumMessage, id=message_id)
    if request.user.role == 'admin' or request.user == message.sender:
        message.delete()
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error', 'message': 'Permission denied'}, status=403)

@login_required
@csrf_protect
def pin_message(request, message_id):
    if request.user.role not in ['admin', 'officer']:
        return JsonResponse({'status': 'error', 'message': 'Permission denied'}, status=403)
    
    message = get_object_or_404(ForumMessage, id=message_id)
    message.is_pinned = not message.is_pinned
    message.save()
    
    return JsonResponse({
        'status': 'success',
        'is_pinned': message.is_pinned
    })


@login_required
def get_notifications(request):
    notifications = Notification.objects.filter(
        user=request.user,
        is_read=False
    ).select_related('message', 'message__sender')
    
    notifications_data = []
    for notif in notifications:
        notifications_data.append({
            'id': notif.id,
            'sender': notif.message.sender.username,
            'content': notif.message.content[:100] + '...' if len(notif.message.content) > 100 else notif.message.content,
            'timestamp': notif.timestamp.strftime('%Y-%m-%d %H:%M')
        })
    
    return JsonResponse({'notifications': notifications_data})

@login_required
def mark_notification_read(request, notification_id):
    notification = get_object_or_404(Notification, id=notification_id, user=request.user)
    notification.is_read = True
    notification.save()
    return JsonResponse({'status': 'success'})

@never_cache
@login_required
def manage_roles(request):
    """View for admins to manage user roles (promote/demote)"""
    if request.user.role != 'admin':
        return redirect('dashboard')
        
    # Get all active users except admin
    users = User.objects.filter(is_archived=False).exclude(username='Mr_Admin')
    
    return render(request, 'manage_roles.html', {'users': users})

@never_cache
@login_required
def add_event(request):
    """View for adding or proposing events"""
    if request.user.role not in ['admin', 'officer']:
        return redirect('dashboard')
        
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        category = request.POST.get('category')
        subcategory = request.POST.get('subcategory')
        street = request.POST.get('street')
        barangay = request.POST.get('barangay')
        city = request.POST.get('city')
        province = request.POST.get('province')
        date_from = request.POST.get('date_from')
        date_until = request.POST.get('date_until')
        is_global = request.POST.get('is_global') == 'on'  # Checkbox value
        
        # Only admin can create global events
        if is_global and request.user.role != 'admin':
            is_global = False
            
        # Handle council selection (admin can choose council or create global event, officer uses their own)
        if request.user.role == 'admin':
            # If global event, no council is assigned
            if is_global:
                council = None
                status = 'approved'  # Admin-created global events are automatically approved
            else:
                council_id = request.POST.get('council_id')
                try:
                    council = Council.objects.get(id=council_id)
                    # Admin-created events are automatically approved
                    status = 'approved'
                except Council.DoesNotExist:
                    messages.error(request, 'Invalid council selected.')
                    return redirect('add_event')
        else:
            council = request.user.council
            if not council:
                messages.error(request, 'You need to be assigned to a council to create events.')
                return redirect('dashboard')
            # Officer-created events need approval
            status = 'pending'
            is_global = False  # Officers cannot create global events
            
        try:
            event = Event.objects.create(
                name=name,
                description=description,
                category=category,
                subcategory=subcategory,
                council=council,
                is_global=is_global,
                street=street,
                barangay=barangay,
                city=city,
                province=province,
                date_from=date_from,
                date_until=date_until,
                status=status,
                created_by=request.user
            )
            
            if status == 'approved':
                event.approved_by = request.user
                event.save()
                messages.success(request, f'Event "{name}" has been created successfully.')
            else:
                messages.success(request, f'Event "{name}" has been proposed and is pending approval.')
                
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f'Error creating event: {str(e)}')
            
    # Get all councils for admin selection
    councils = Council.objects.all() if request.user.role == 'admin' else None
    
    return render(request, 'add_event.html', {'councils': councils, 'is_admin': request.user.role == 'admin'})

@never_cache
@login_required
def edit_event(request, event_id):
    """View for editing an event"""
    # Get the event or return 404
    event = get_object_or_404(Event, id=event_id)
    
    # Security check - only admins or the event creator can edit
    if request.user.role != 'admin' and request.user != event.created_by:
        messages.error(request, "You don't have permission to edit this event.")
        return redirect('dashboard')
        
    if request.method == 'POST':
        # Process the form data
        event.name = request.POST.get('name')
        event.description = request.POST.get('description')
        event.category = request.POST.get('category')
        event.subcategory = request.POST.get('subcategory')
        event.street = request.POST.get('street')
        event.barangay = request.POST.get('barangay')
        event.city = request.POST.get('city')
        event.province = request.POST.get('province')
        event.date_from = request.POST.get('date_from')
        event.date_until = request.POST.get('date_until')
        
        # Only admins can change the council or global status
        if request.user.role == 'admin':
            is_global = request.POST.get('is_global') == 'on'
            event.is_global = is_global
            
            # If global, remove council association
            if is_global:
                event.council = None
            # If not global, set council from selection
            elif request.POST.get('council_id'):
                try:
                    council = Council.objects.get(id=request.POST.get('council_id'))
                    event.council = council
                except Council.DoesNotExist:
                    messages.error(request, 'Invalid council selected.')
                    return redirect('edit_event', event_id=event_id)
        
        try:
            event.save()
            messages.success(request, f'Event "{event.name}" has been updated successfully.')
            
            # Always redirect to dashboard instead of admin_dashboard or other specific dashboards
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f'Error updating event: {str(e)}')
    
    # For GET request, prepare the form
    councils = Council.objects.all() if request.user.role == 'admin' else None
    
    # Pass the event and councils to the template
    return render(request, 'edit_event.html', {
        'event': event,
        'councils': councils,
        'is_admin': request.user.role == 'admin'
    })

@never_cache
@login_required
def event_proposals(request):
    """View for admins to manage event proposals"""
    if request.user.role != 'admin':
        return redirect('dashboard')
        
    # Get pending events
    pending_events = Event.objects.filter(status='pending')
    
    # Get previously processed events (approved or rejected)
    previous_events = Event.objects.filter(
        Q(status='approved') | Q(status='rejected')
    ).order_by('-updated_at')[:20]  # Limit to 20 most recent
    
    return render(request, 'event_proposals.html', {
        'pending_events': pending_events,
        'previous_events': previous_events
    })

@never_cache
@login_required
def approve_event(request, event_id):
    """Approve an event proposal"""
    if request.user.role != 'admin':
        return redirect('dashboard')
        
    event = get_object_or_404(Event, id=event_id)
    
    if event.status == 'pending':
        event.status = 'approved'
        event.approved_by = request.user
        event.save()
        messages.success(request, f'Event "{event.name}" has been approved.')
        
    return redirect('event_proposals')

@never_cache
@login_required
def reject_event(request, event_id):
    """Reject an event proposal"""
    if request.user.role != 'admin':
        return redirect('dashboard')
        
    event = get_object_or_404(Event, id=event_id)
    
    if event.status == 'pending':
        if request.method == 'POST':
            rejection_category = request.POST.get('rejection_category', '')
            custom_reason = request.POST.get('custom_reason', '')
            additional_notes = request.POST.get('additional_notes', '')
            
            # Build the final rejection reason
            if rejection_category == 'Others':
                final_reason = f"Others: {custom_reason}"
            else:
                final_reason = rejection_category
            
            # Add additional notes if provided
            if additional_notes:
                final_reason += f"\n\nAdditional Notes: {additional_notes}"
            
            event.status = 'rejected'
            event.rejection_reason = final_reason
            event.save()
            messages.success(request, f'Event "{event.name}" has been rejected.')
            return redirect('event_proposals')
        else:
            # Show rejection form
            return render(request, 'reject_event.html', {'event': event})
    else:
        messages.error(request, 'Only pending events can be rejected.')
    
    return redirect('event_proposals')

@never_cache
@login_required
def event_details(request, event_id):
    """API endpoint for event details"""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Not authorized'}, status=401)
        
    event = get_object_or_404(Event, id=event_id)
    
    # If not admin, users can only see their council's events, global events, or approved events
    if request.user.role != 'admin':
        if not event.is_global and event.council != request.user.council and event.status != 'approved':
            return JsonResponse({'error': 'Not authorized'}, status=403)
    
    data = {
        'id': event.id,
        'name': event.name,
        'description': event.description,
        'category': event.category,
        'date_from': event.date_from.strftime('%b %d, %Y'),
        'council_name': event.council.name if event.council else "All Councils",
        'is_global': event.is_global,
        'street': event.street,
        'barangay': event.barangay,
        'city': event.city,
        'province': event.province,
        'status': event.status,
        'status_display': event.get_status_display(),
        'creator_name': f"{event.created_by.first_name} {event.created_by.last_name}" if event.created_by else "Unknown"
    }
    
    if event.date_until and event.date_until != event.date_from:
        data['date_until'] = event.date_until.strftime('%b %d, %Y')
    
    if event.status == 'rejected' and event.rejection_reason:
        data['rejection_reason'] = event.rejection_reason
    
    return JsonResponse(data)

@never_cache
@login_required
def archived_events(request):
    """View for displaying archived (past) events with filtering options"""
    from datetime import date
    today = date.today()
    
    user = request.user
    if not user.is_authenticated or user.role == 'pending':
        return redirect('sign-in')
        
    # Get past events based on user role (events that have ended)
    past_events_query = Q(date_from__lt=today) & Q(Q(date_until__lt=today) | Q(date_until__isnull=True))
    
    # Include rejected events regardless of date
    rejected_events_query = Q(status='rejected')
    
    # Combined query for past events or rejected events
    combined_query = past_events_query | rejected_events_query
    
    if user.role == 'admin':
        # Admin sees all past events and all rejected events
        past_events = Event.objects.filter(combined_query)
        
    elif user.role in ['officer', 'member']:
        # Officers and members see their council's past events, global events, and rejected events
        past_events = Event.objects.filter(
            combined_query & (Q(council=user.council) | Q(is_global=True))
        )
    else:
        return redirect('dashboard')
        
    # Sort events based on user preference
    sort_by = request.GET.get('sort', 'date_desc')
    if sort_by == 'name':
        past_events = past_events.order_by('name')
    elif sort_by == 'date':
        past_events = past_events.order_by('date_from')
    elif sort_by == 'category':
        past_events = past_events.order_by('category', '-date_from')
    else:  # Default: date descending (most recent first)
        past_events = past_events.order_by('-date_from')
    
    # Filter by category if specified
    category_filter = request.GET.get('category', None)
    if category_filter and category_filter != 'all':
        past_events = past_events.filter(category=category_filter)
    
    # Filter by status if specified
    status_filter = request.GET.get('status', None)
    if status_filter and status_filter != 'all':
        past_events = past_events.filter(status=status_filter)
    
    # Filter by council if specified (for admin users)
    council_filter = request.GET.get('council', None)
    if council_filter and council_filter != 'all' and user.role == 'admin':
        past_events = past_events.filter(council_id=council_filter)
        
    context = {
        'past_events': past_events,
        'user': user,
        'sort_by': sort_by,
        'category_filter': category_filter,
        'status_filter': status_filter,
        'council_filter': council_filter,
        'councils': Council.objects.all() if user.role == 'admin' else None,
    }
    
    return render(request, 'archived_events.html', context)

@never_cache
def donations(request):
    show_manual_link = request.user.is_authenticated and request.user.role in ['admin', 'officer']
    logger.debug(f"show_manual_link: {show_manual_link}, User: {request.user}, Role: {getattr(request.user, 'role', 'N/A')}")
    if request.method == 'POST':
        form = DonationForm(request.POST, request.FILES)
        logger.debug(f"Form fields: {form.as_p()}")
        if form.is_valid():
            donation = form.save(commit=False)
            donation.submitted_by = request.user if request.user.is_authenticated else None
            donation.transaction_id = f"GCASH-{uuid.uuid4().hex[:8]}"
            donation.payment_method = 'gcash'
            donation.status = 'pending'
            donation.signature = ''
            donation.donation_date = date.today()
            donation.save()
            logger.info(f"GCash donation created: ID={donation.id}, Email={donation.email}, Amount={donation.amount}")
            return initiate_gcash_payment(request, donation)
        else:
            logger.debug(f"Form errors: {form.errors}")
            messages.error(request, 'Please correct the errors in the form.')
    else:
        form = DonationForm(initial={'donation_date': date.today()})
        logger.debug(f"Rendered form HTML: {form.as_p()}")
    return render(request, 'donations.html', {'form': form, 'show_manual_link': show_manual_link})

@csrf_protect
@login_required
# @permission_required('capstone_project.add_manual_donation', raise_exception=True)
def manual_donation(request):
    if request.method == 'POST':
        logger.debug(f"POST data: {dict(request.POST)}")
        form = ManualDonationForm(request.POST, request.FILES)
        if form.is_valid():
            donation = form.save(commit=False)
            donation.payment_method = 'manual'
            donation.submitted_by = request.user
            # Assign the council of the submitting user
            if request.user.council:
                donation.council = request.user.council
            else:
                messages.error(request, 'You must be assigned to a council to submit a donation.')
                return redirect('donations')
            donation.transaction_id = f"KC-{uuid.uuid4().hex[:8]}"
            donation.source_id = ''
            donation.status = 'pending_manual'
            # If donating anonymously, clear personal fields
            if form.cleaned_data.get('donate_anonymously'):
                donation.first_name = "Anonymous"
                donation.middle_initial = ""
                donation.last_name = ""
                donation.email = ""
            donation.save()
            logger.info(f"Manual donation created: ID={donation.id}, Email={donation.email or 'Anonymous'}, Amount={donation.amount}, Status={donation.status}, Council={donation.council.name if donation.council else 'None'}")
            messages.success(request, 'Manual donation submitted for review.')
            return redirect('donations')
        else:
            logger.debug(f"Form errors: {form.errors}")
            messages.error(request, 'Please correct the errors in the form.')
    else:
        form = ManualDonationForm(initial={'donation_date': date.today()})
    return render(request, 'add_manual_donation.html', {'form': form})


@csrf_protect
@login_required
# @permission_required('capstone_project.review_manual_donations', raise_exception=True)
def review_manual_donations(request):
    if request.user.role == 'admin':
        pending_donations = Donation.objects.filter(status='pending_manual')
    else:  # Officer
        pending_donations = Donation.objects.filter(status='pending_manual').filter(
            submitted_by__council=request.user.council
        ).exclude(submitted_by=request.user)

    logger.debug(f"User {request.user.username} (role={request.user.role}, council={request.user.council.name if request.user.council else 'None'}): Found {pending_donations.count()} pending manual donations")
    for donation in pending_donations:
        logger.debug(f"Donation ID={donation.id}, Transaction={donation.transaction_id}, Submitted by={donation.submitted_by.username if donation.submitted_by else 'None'}, Council={donation.submitted_by.council.name if donation.submitted_by and donation.submitted_by.council else 'None'}")

    paginator = Paginator(pending_donations, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.method == 'POST':
        logger.debug("Updated review_manual_donations view applied - May 28, 19:26 PST fix")
        donation_id = request.POST.get('donation_id')
        action = request.POST.get('action')
        rejection_reason = request.POST.get('rejection_reason', '')

        try:
            donation = Donation.objects.get(id=donation_id, status='pending_manual')
            # Council restriction for officers
            if request.user.role == 'officer' and donation.submitted_by and donation.submitted_by.council and donation.submitted_by.council != request.user.council:
                messages.error(request, 'You are not authorized to review this donation.')
                return redirect('review_manual_donations')
            # Prevent self-review
            if donation.submitted_by == request.user:
                messages.error(request, 'You cannot review your own donation.')
                return redirect('review_manual_donations')

            with transaction.atomic():
                if action == 'approve':
                    donation.status = 'completed'
                    donation.reviewed_by = request.user
                    # Use the globally defined keys from views.py
                    logger.debug(f"Using global keys: PRIVATE_KEY={PRIVATE_KEY is not None}, PUBLIC_KEY={PUBLIC_KEY is not None}")
                    if not PRIVATE_KEY or not PUBLIC_KEY:
                        raise ValueError("Private or public key not loaded in views.py")
                    logger.debug("Attempting to sign donation")
                    donation.sign_donation(PRIVATE_KEY)
                    donation.save()
                    logger.debug("Donation signed and saved")
                    # Initialize blockchain instance
                    blockchain_instance = getattr(blockchain, 'initialize_chain', None)
                    if callable(blockchain_instance):
                        blockchain_instance()
                    else:
                        blockchain.initialize_chain()  # Fallback if method not callable
                    logger.debug("Blockchain initialized")

                    # Handle blockchain transaction in a separate function
                    def process_blockchain_transaction():
                        nonlocal donation
                        try:
                            transaction = blockchain.add_transaction(donation, PUBLIC_KEY)
                            logger.debug(f"Transaction added: {transaction}")
                            return bool(transaction)
                        except Exception as e:
                            logger.error(f"Failed to add transaction to blockchain for donation {donation.transaction_id}: {str(e)}", exc_info=True)
                            raise

                    transaction_result = process_blockchain_transaction()
                    if transaction_result:
                        previous_block = blockchain.get_previous_block()
                        previous_proof = previous_block['proof'] if previous_block else 0
                        logger.debug(f"Previous proof: {previous_proof}")
                        proof = blockchain.proof_of_work(previous_proof)
                        logger.debug(f"Proof of work completed: {proof}")
                        new_block = blockchain.create_block(proof)
                        logger.debug(f"New block created: {new_block}")
                        if new_block:
                            logger.info(f"New block created for manual donation: Index={new_block['index']}, Transactions={len(new_block['transactions'])}")
                            messages.success(request, f"Donation {donation.transaction_id} approved and recorded on the blockchain.")
                        else:
                            logger.error("Failed to create block for donation")
                            donation.status = 'pending_manual'
                            donation.save()
                            messages.error(request, "Failed to record donation on blockchain.")
                    else:
                        logger.error(f"Invalid signature for donation {donation.transaction_id}")
                        donation.status = 'pending_manual'
                        donation.save()
                        messages.error(request, "Invalid donation signature.")
                elif action == 'reject':
                    donation.status = 'failed'
                    donation.reviewed_by = request.user
                    donation.rejection_reason = rejection_reason
                    donation.save()
                    logger.info(f"Manual Donation {donation.transaction_id} rejected by {request.user.username}, reason={rejection_reason}")
                    messages.success(request, f"Donation {donation.transaction_id} rejected.")
                else:
                    messages.error(request, 'Invalid action.')
        except Donation.DoesNotExist:
            logger.error(f"Donation {donation_id} not found or already reviewed")
            messages.error(request, 'Donation not found or already reviewed.')
        except ValueError as e:
            logger.error(f"Configuration error: {str(e)}")
            messages.error(request, str(e))
        except Exception as e:
            logger.error(f"Unexpected error processing donation {donation_id}: {str(e)}", exc_info=True)
            messages.error(request, "An unexpected error occurred. Please contact support.")
        return redirect('review_manual_donations')

    return render(request, 'review_manual_donations.html', {'page_obj': page_obj})
def initiate_gcash_payment(request, donation):
    logger.debug(f"Initiating GCash payment for donation ID={donation.id}, Amount={donation.amount}")
    amount = int(donation.amount * 100)
    if amount < 10000:
        donation.status = 'failed'
        donation.save()
        messages.error(request, 'Donation amount must be at least ₱100.')
        return redirect('donations')

    paymongo_secret_key = getattr(settings, 'PAYMONGO_SECRET_KEY', '')
    if not paymongo_secret_key:
        logger.error("PayMongo secret key not configured in settings")
        donation.status = 'failed'
        donation.save()
        messages.error(request, "Payment system is currently unavailable. Please try again later.")
        return redirect('donations')

    request.session['donation_id'] = donation.id
    request.session.modified = True

    auth_key = base64.b64encode(f"{paymongo_secret_key}:".encode()).decode()
    url = f"{PAYMONGO_API_URL}/sources"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Basic {auth_key}"
    }
    donor_name = f"{donation.first_name} {donation.middle_initial}. {donation.last_name}".strip() or "Anonymous"
    payload = {
        "data": {
            "attributes": {
                "amount": amount,
                "currency": "PHP",
                "type": "gcash",
                "redirect": {
                    "success": request.build_absolute_uri(reverse('confirm_gcash_payment')),
                    "failed": request.build_absolute_uri(reverse('cancel_page'))
                },
                "billing": {
                    "name": donor_name,
                    "email": donation.email
                },
                "metadata": {
                    "donation_id": str(donation.id),
                    "transaction_id": donation.transaction_id
                }
            }
        }
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        donation.source_id = data['data']['id']
        donation.save()
        logger.info(f"PayMongo source created: Source ID={data['data']['id']}, Donation ID={donation.id}")
        return redirect(data['data']['attributes']['redirect']['checkout_url'])
    except requests.exceptions.RequestException as e:
        error_detail = e.response.json().get('errors', [{}])[0].get('detail', str(e)) if e.response else str(e)
        logger.error(f"PayMongo API error for donation ID {donation.id}: {error_detail}")
        donation.status = 'failed'
        donation.save()
        messages.error(request, f"Failed to initiate payment: {error_detail}")
        return redirect('donations')
    
@csrf_protect
def confirm_gcash_payment(request):
    logger.debug(f"Session data: {request.session.items()}")
    donation_id = request.session.get('donation_id') or request.GET.get('donation_id')
    source_id = request.GET.get('source_id')

    if not donation_id:
        logger.error("Missing donation_id in GCash confirmation")
        messages.error(request, "Invalid payment confirmation request: Missing donation ID.")
        return redirect('donations')

    try:
        donation = get_object_or_404(Donation, id=donation_id, payment_method='gcash', status='pending')
        
        if not source_id:
            source_id = donation.source_id
            if not source_id:
                logger.error(f"No source_id available for donation ID {donation_id}")
                donation.status = 'failed'
                donation.save()
                messages.error(request, "Invalid payment confirmation: Missing source ID.")
                return redirect('donations')

        paymongo_secret_key = getattr(settings, 'PAYMONGO_SECRET_KEY', '')
        if not paymongo_secret_key:
            logger.error("PayMongo secret key not configured")
            donation.status = 'failed'
            donation.save()
            messages.error(request, "Payment verification failed due to configuration error.")
            return redirect('donations')

        auth_key = base64.b64encode(f"{paymongo_secret_key}:".encode()).decode()
        headers = {
            "Accept": "application/json",
            "Authorization": f"Basic {auth_key}"
        }
        response = requests.get(f"{PAYMONGO_API_URL}/sources/{source_id}", headers=headers)
        response.raise_for_status()
        source_data = response.json()
        logger.debug(f"PayMongo source response: {source_data}")

        if source_data['data']['attributes']['status'] != 'chargeable':
            logger.error(f"Invalid source status for donation ID {donation_id}: {source_data['data']['attributes']['status']}")
            donation.status = 'failed'
            donation.save()
            messages.error(request, "Payment could not be verified.")
            return redirect('donations')

        with transaction.atomic():
            donation.status = 'completed'
            donation.source_id = source_id
            try:
                donation.sign_donation(PRIVATE_KEY)
            except Exception as e:
                logger.error(f"Failed to sign donation ID {donation.id}: {str(e)}")
                donation.status = 'pending'
                donation.save()
                messages.error(request, "Payment processed but failed to sign donation. Contact support.")
                raise

            donation.save()

            blockchain.initialize_chain()
            try:
                transaction_result = blockchain.add_transaction(donation, PUBLIC_KEY)
                if transaction_result:
                    previous_block = blockchain.get_previous_block()
                    previous_proof = previous_block['proof'] if previous_block else 0
                    proof = blockchain.proof_of_work(previous_proof)
                    block = blockchain.create_block(proof)
                    if block:
                        logger.info(f"Block created for donation ID {donation.id}, Transaction ID {donation.transaction_id}")
                        blockchain.refresh_from_db()
                        logger.debug(f"Pending transactions after block creation: {blockchain.pending_transactions}")
                        messages.success(request, "Payment successful! Donation recorded on the blockchain.")
                    else:
                        logger.error(f"Failed to create block for donation ID {donation.id}")
                        donation.status = 'pending'
                        donation.save()
                        messages.error(request, "Payment processed but failed to record on blockchain. Contact support.")
                        raise Exception("Blockchain recording failed")
                else:
                    logger.error(f"Failed to add transaction for donation ID {donation.id}: Invalid transaction data or signature")
                    donation.status = 'pending'
                    donation.save()
                    messages.error(request, "Payment processed but failed to record donation due to invalid signature. Contact support.")
                    raise Exception("Transaction recording failed")
            except Exception as e:
                logger.error(f"Error adding transaction for donation ID {donation.id}: {str(e)}")
                donation.status = 'pending'
                donation.save()
                messages.error(request, "Payment processed but failed to record donation due to blockchain error. Contact support.")
                raise

        if 'donation_id' in request.session:
            del request.session['donation_id']
            request.session.modified = True

    except Donation.DoesNotExist:
        logger.error(f"Donation ID {donation_id} not found or invalid")
        messages.error(request, "Donation not found or already processed.")
    except requests.exceptions.RequestException as e:
        error_detail = e.response.json().get('errors', [{}])[0].get('detail', str(e)) if e.response else str(e)
        logger.error(f"PayMongo verification error for donation ID {donation_id}: {error_detail}")
        donation.status = 'failed'
        donation.save()
        messages.error(request, "Payment verification failed.")
    except Exception as e:
        logger.error(f"Unexpected error in GCash confirmation for donation ID {donation_id}: {str(e)}")
        donation.status = 'failed'
        donation.save()
        messages.error(request, "An error occurred while processing your payment. Please try again.")
    return redirect('donations')

@never_cache
@login_required
def get_blockchain_data(request):
    logger.debug("Fetching blockchain data")
    try:
        chain = blockchain.get_chain()
        if not blockchain.is_chain_valid():
            logger.error("Blockchain validation failed")
            messages.error(request, "Blockchain data is corrupted. Contact support.")
            return redirect('donations')
        pending_transactions = blockchain.pending_transactions

        # Preprocess chain: Ensure dates are in 'YYYY-MM-DD' format
        for block in chain:
            for tx in block['transactions']:
                if 'date' in tx and tx['date']:
                    try:
                        # Ensure the date remains in 'YYYY-MM-DD' format
                        date_obj = datetime.strptime(tx['date'], '%Y-%m-%d')
                        tx['donation_date'] = date_obj.strftime('%Y-%m-%d')
                    except ValueError:
                        logger.error(f"Invalid date format in transaction {tx.get('transaction_id')}: {tx['date']}")
                        tx['donation_date'] = 'N/A'
                else:
                    tx['donation_date'] = 'N/A'
                # Ensure status is present
                if 'status' not in tx:
                    tx['status'] = 'Unknown'

        # Preprocess pending transactions
        for tx in pending_transactions:
            if 'date' in tx and tx['date']:
                try:
                    date_obj = datetime.strptime(tx['date'], '%Y-%m-%d')
                    tx['donation_date'] = date_obj.strftime('%Y-%m-%d')
                except ValueError:
                    logger.error(f"Invalid date format in pending transaction {tx.get('transaction_id')}: {tx['date']}")
                    tx['donation_date'] = 'N/A'
            else:
                tx['donation_date'] = 'N/A'
            # Ensure status is present
            if 'status' not in tx:
                tx['status'] = 'Unknown'

        logger.info(f"Blockchain data retrieved: {len(chain)} blocks, {len(pending_transactions)} pending transactions")
        return render(request, 'blockchain.html', {
            'chain': chain,
            'pending_transactions': pending_transactions
        })
    except Exception as e:
        logger.error(f"Error fetching blockchain data: {str(e)}")
        messages.error(request, "Unable to retrieve blockchain data. Please try again later.")
        return redirect('donations')
           
def success_page(request):
    return render(request, 'success.html', {'message': 'Payment processing. Awaiting confirmation.'})

def cancel_page(request):
    donation_id = request.GET.get('donation_id')
    if donation_id:
        try:
            donation = get_object_or_404(Donation, id=donation_id, payment_method='gcash')
            donation.status = 'failed'
            donation.save()
            logger.info(f"Donation {donation.transaction_id} marked as failed due to cancellation")
        except Exception as e:
            logger.error(f"Error marking donation {donation_id} as failed: {str(e)}")
    logger.error("Payment cancelled")
    messages.error(request, "Payment was cancelled or failed.")
    return render(request, 'cancel.html', {'error': 'Payment was cancelled or failed.'})

@never_cache
@login_required
def event_list(request):
    """View for displaying a list of all events with filtering options"""
    from datetime import date
    today = date.today()
    
    # Only show current and future events, past events should be in archived_events
    base_query = Q(date_from__gte=today) | Q(date_until__gte=today)
    
    # Get status filter first
    status_filter = request.GET.get('status', None)
    
    # Filter events based on user role
    if request.user.role == 'member':
        # Members can only see approved events from their own council or global events
        events = Event.objects.filter(
            base_query & 
            Q(status='approved') & 
            (Q(council=request.user.council) | Q(is_global=True))
        )
    elif request.user.role == 'officer':
        # Officers can see events from their own council or global events
        # They can see all statuses for their own events, but only approved for others
        if status_filter and status_filter != 'all':
            if status_filter == 'approved':
                events = Event.objects.filter(
                    base_query & 
                    Q(status='approved') & 
                    (Q(council=request.user.council) | Q(is_global=True))
                )
            else:
                # For pending/rejected, only show their own events
                events = Event.objects.filter(
                    base_query & 
                    Q(status=status_filter) & 
                    Q(created_by=request.user) &
                    (Q(council=request.user.council) | Q(is_global=True))
                )
        else:
            # Default: show approved events from their council + their own events of any status
            events = Event.objects.filter(
                base_query & 
                (
                    (Q(status='approved') & (Q(council=request.user.council) | Q(is_global=True))) |
                    Q(created_by=request.user)
                )
            )
    else:
        # Admins see all events from all councils
        events = Event.objects.filter(base_query)
        
        # Apply status filter for admins
        if status_filter and status_filter != 'all':
            events = events.filter(status=status_filter)
    
    # Filter by category if specified
    category_filter = request.GET.get('category', None)
    if category_filter and category_filter != 'all':
        events = events.filter(category=category_filter)
    
    # Filter by council if specified (for admin users)
    council_filter = request.GET.get('council', None)
    if council_filter and council_filter != 'all' and request.user.role == 'admin':
        events = events.filter(council_id=council_filter)
    
    # Sort events based on user preference
    sort_by = request.GET.get('sort', 'date')
    if sort_by == 'name':
        events = events.order_by('name')
    elif sort_by == 'date_desc':
        events = events.order_by('-date_from')
    elif sort_by == 'category':
        events = events.order_by('category', 'date_from')
    else:  # Default: date ascending (soonest first)
        events = events.order_by('date_from')
    
    # Get all councils for filter dropdown (admin only)
    councils = None
    if request.user.role == 'admin':
        councils = Council.objects.all()
    
    # Check if events are happening today (for officers to manage attendance)
    for event in events:
        event.is_today = (event.date_from <= today <= (event.date_until or event.date_from))
    
    context = {
        'events': events,
        'councils': councils,
        'status_filter': status_filter,
        'category_filter': category_filter,
        'council_filter': council_filter,
        'sort_by': sort_by,
    }
    
    return render(request, 'event_list.html', context)

def member_list(request):
    """View for displaying a list of all members (for admin users)"""
    if request.user.role != 'admin':
        return redirect('dashboard')
    
    users = User.objects.filter(is_active=True).exclude(role='admin')
    
    # Filter by role if specified
    role_filter = request.GET.get('role', None)
    if role_filter and role_filter != 'all':
        users = users.filter(role=role_filter)
    
    # Filter by council if specified
    council_filter = request.GET.get('council', None)
    if council_filter and council_filter != 'all':
        users = users.filter(council_id=council_filter)
    
    # Filter by degree if specified
    degree_filter = request.GET.get('degree', None)
    if degree_filter and degree_filter != 'all':
        users = users.filter(current_degree=degree_filter)
    
    # Search by name if specified
    search_query = request.GET.get('search', None)
    if search_query:
        users = users.filter(
            Q(first_name__icontains=search_query) | 
            Q(last_name__icontains=search_query) |
            Q(email__icontains=search_query)
        )
    
    councils = Council.objects.all()
    
    context = {
        'users': users,
        'councils': councils,
        'role_filter': role_filter,
        'council_filter': council_filter,
        'degree_filter': degree_filter,
        'search_query': search_query,
    }
    
    return render(request, 'member_list.html', context)

def council_members(request):
    """View for displaying members of a specific council (for officer users)"""
    if request.user.role not in ['admin', 'officer']:
        return redirect('dashboard')
    
    # Officers can only see members of their own council
    if request.user.role == 'officer':
        council = request.user.council
        users = User.objects.filter(council=council, is_active=True)
    else:
        # Admin can see all members but can filter by council
        council_id = request.GET.get('council', None)
        if council_id:
            council = Council.objects.get(id=council_id)
            users = User.objects.filter(council=council, is_active=True)
        else:
            users = User.objects.filter(is_active=True)
            council = None
    
    # Filter by role if specified
    role_filter = request.GET.get('role', None)
    if role_filter and role_filter != 'all':
        users = users.filter(role=role_filter)
    
    # Filter by degree if specified
    degree_filter = request.GET.get('degree', None)
    if degree_filter and degree_filter != 'all':
        users = users.filter(current_degree=degree_filter)
    
    # Search by name if specified
    search_query = request.GET.get('search', None)
    if search_query:
        users = users.filter(
            Q(first_name__icontains=search_query) | 
            Q(last_name__icontains=search_query) |
            Q(email__icontains=search_query)
        )
    
    context = {
        'users': users,
        'council': council,
        'role_filter': role_filter,
        'degree_filter': degree_filter,
        'search_query': search_query,
    }
    
    return render(request, 'council_members.html', context)

@never_cache
@login_required
def council_events(request):
    """View for displaying events of a specific council (for officer users)"""
    if request.user.role not in ['admin', 'officer']:
        return redirect('dashboard')
    
    today = date.today()
    
    # Officers can only see events of their own council
    if request.user.role == 'officer':
        council = request.user.council
        # Get events for this council AND global events
        events = Event.objects.filter(
            Q(council=council) | Q(is_global=True)
        )
    else:
        # Admin can see all events but can filter by council
        council_id = request.GET.get('council', None)
        if council_id:
            council = Council.objects.get(id=council_id)
            events = Event.objects.filter(council=council)
        else:
            events = Event.objects.all()
            council = None
    
    # Filter by category if specified
    category_filter = request.GET.get('category', None)
    if category_filter and category_filter != 'all':
        events = events.filter(category=category_filter)
    
    # Get status filter
    status_filter = request.GET.get('status', None)
    
    # Mark events as today, upcoming, or past
    todays_events = []
    upcoming_events = []
    past_events = []
    rejected_events = []
    
    for event in events:
        # Check if the event is happening today
        event.is_today = (event.date_from <= today <= (event.date_until or event.date_from))
        
        # If filtering by status, only include matching events
        if status_filter and status_filter != 'all' and event.status != status_filter:
            continue
            
        # Categorize events by date and status
        if event.status == 'rejected':
            rejected_events.append(event)
        elif event.is_today:
            todays_events.append(event)
        elif event.date_from > today:
            upcoming_events.append(event)
        elif (event.date_until or event.date_from) < today:
            past_events.append(event)
    
    # Sort events: approved first, then by proximity to today
    def sort_key(event):
        # Primary sort: approved status (True/False)
        # Secondary sort: date proximity to today
        is_approved = event.status == 'approved'
        days_to_event = (event.date_from - today).days if event.date_from >= today else 1000
        return (-1 if is_approved else 0, days_to_event)
    
    # Sort upcoming events
    upcoming_events.sort(key=sort_key)
    
    # Sort today's events (approved first)
    todays_events.sort(key=lambda event: 0 if event.status == 'approved' else 1)
    
    # If filtering by rejected status, show rejected events in main list
    if status_filter == 'rejected':
        sorted_events = rejected_events
    else:
        # Combine events: today's events first, then upcoming
        sorted_events = todays_events + upcoming_events
    
    context = {
        'events': sorted_events,
        'past_events': past_events + rejected_events,  # Include rejected events with past events
        'council': council,
        'status_filter': status_filter,
        'category_filter': category_filter,
        'today': today,
        'has_todays_events': len(todays_events) > 0,
    }
    
    return render(request, 'council_events.html', context)

def update_degree(request, user_id):
    """View for updating a member's degree"""
    if request.user.role not in ['admin', 'officer']:
        return redirect('dashboard')
    
    user = get_object_or_404(User, id=user_id)
    
    # Check if officer is trying to update a user from another council
    if request.user.role == 'officer' and user.council != request.user.council:
        messages.error(request, "You can only update members from your own council.")
        return redirect('council_members')
    
    if request.method == 'POST':
        new_degree = request.POST.get('degree')
        if new_degree in [choice[0] for choice in User.DEGREE_CHOICES]:
            user.current_degree = new_degree
            user.save()
            messages.success(request, f"{user.first_name}'s degree has been updated successfully.")
            
            # Redirect based on user role
            if request.user.role == 'admin':
                return redirect('member_list')
            else:
                return redirect('council_members')
        else:
            messages.error(request, "Invalid degree selection.")
    
    context = {
        'user': user,
        'degree_choices': User.DEGREE_CHOICES,
    }
    
    return render(request, 'update_degree.html', context)

@login_required
def user_details(request, user_id):
    """API endpoint for user details"""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Not authorized'}, status=401)
        
    user = get_object_or_404(User, id=user_id)
    
    # If officer, they can only see details of users in their council
    if request.user.role == 'officer' and user.council != request.user.council:
        return JsonResponse({'error': 'Not authorized'}, status=403)
    
    data = {
        'id': user.id,
        'username': user.username,
        'first_name': user.first_name,
        'second_name': user.second_name,
        'last_name': user.last_name,
        'middle_name': user.middle_name,
        'middle_initial': user.middle_initial,
        'suffix': user.suffix,
        'email': user.email,
        'contact_number': user.contact_number,
        'birthday': user.birthday.strftime('%b %d, %Y') if user.birthday else None,
        'age': user.age,
        'street': user.street,
        'barangay': user.barangay,
        'city': user.city,
        'province': user.province,
        'zip_code': user.zip_code,
        'role': user.role,
        'role_display': user.get_role_display(),
        'council_name': user.council.name if user.council else None,
        'degree_display': user.get_current_degree_display(),
        'date_joined': user.date_joined.strftime('%b %d, %Y'),
        'marital_status': user.marital_status,
        'occupation': user.occupation,
        'recruiter_name': user.recruiter_name,
        'voluntary_join': user.voluntary_join,
        'join_reason': user.join_reason,
    }
    
    if user.profile_picture:
        data['profile_picture'] = user.profile_picture.url
        
    if user.e_signature:
        data['e_signature'] = user.e_signature.url
    
    return JsonResponse(data)

@never_cache
@login_required
def event_attendance(request, event_id):
    """View for managing event attendance"""
    # Only officers and admins can manage attendance
    if request.user.role not in ['admin', 'officer']:
        return redirect('dashboard')
    
    # Get the event
    event = get_object_or_404(Event, id=event_id)
    
    # Check if the event is approved
    if event.status != 'approved':
        messages.error(request, 'You can only manage attendance for approved events.')
        return redirect('event_list')
    
    # Check if the officer belongs to the event's council
    if request.user.role == 'officer' and event.council != request.user.council and not event.is_global:
        messages.error(request, 'You can only manage attendance for events in your council.')
        return redirect('event_list')
    
    # Check if the event is happening today
    today = date.today()
    is_today = (event.date_from <= today <= (event.date_until or event.date_from))
    
    # Get members based on the event's council or global status
    if event.is_global:
        if request.user.role == 'admin':
            # Admin can see all members for global events
            members = User.objects.filter(role='member', is_active=True, is_archived=False).order_by('first_name', 'last_name')
        else:
            # Officers can only see members from their council for global events
            members = User.objects.filter(council=request.user.council, role='member', is_active=True, is_archived=False).order_by('first_name', 'last_name')
    else:
        members = User.objects.filter(council=event.council, role='member', is_active=True, is_archived=False).order_by('first_name', 'last_name')
    
    # Get existing attendance records
    attendance_records = EventAttendance.objects.filter(event=event)
    attendance = [record.member.id for record in attendance_records.filter(is_present=True)]
    present_count = len(attendance)
    
    # Create attendance records for members who don't have one yet
    with transaction.atomic():
        for member in members:
            EventAttendance.objects.get_or_create(
                event=event,
                member=member,
                defaults={
                    'is_present': False,
                    'recorded_by': request.user
                }
            )
    
    context = {
        'event': event,
        'members': members,
        'attendance': attendance,
        'present_count': present_count,
        'is_today': is_today,
    }
    
    return render(request, 'event_attendance.html', context)

@never_cache
@login_required
def update_attendance(request):
    """API endpoint for updating event attendance"""
    if request.user.role not in ['admin', 'officer'] or request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Unauthorized'}, status=403)
    
    try:
        data = json.loads(request.body)
        event_id = data.get('event_id')
        
        # Check if this is a batch update or individual update
        if 'present_members' in data:
            # Batch update
            present_members = data.get('present_members', [])
            
            # Validate input
            if not event_id:
                return JsonResponse({'status': 'error', 'message': 'Missing event ID'}, status=400)
            
            try:
                # Get event
                event = get_object_or_404(Event, id=event_id)
                
                # Check if the event is approved
                if event.status != 'approved':
                    return JsonResponse({'status': 'error', 'message': 'Can only update attendance for approved events'}, status=400)
                
                # Check if the officer belongs to the event's council
                if request.user.role == 'officer' and event.council != request.user.council and not event.is_global:
                    return JsonResponse({'status': 'error', 'message': 'You can only manage attendance for events in your council'}, status=403)
                
                # For testing purposes, bypass the date check
                # Check if the event is happening today
                today = date.today()
                if not (event.date_from <= today <= (event.date_until or event.date_from)):
                    # Temporarily comment out this check for testing
                    # return JsonResponse({'status': 'error', 'message': 'Can only update attendance on the day of the event'}, status=400)
                    pass
                
                # Get all members for this event
                if event.is_global:
                    if request.user.role == 'admin':
                        # Admin can see all members for global events
                        members = User.objects.filter(role='member', is_active=True, is_archived=False)
                    else:
                        # Officers can only see members from their council for global events
                        members = User.objects.filter(council=request.user.council, role='member', is_active=True, is_archived=False)
                else:
                    members = User.objects.filter(council=event.council, role='member', is_active=True, is_archived=False)
                
                # Update all attendance records
                with transaction.atomic():
                    # First, mark all as absent
                    EventAttendance.objects.filter(event=event).update(is_present=False)
                    
                    # Then mark selected members as present
                    for member_id in present_members:
                        try:
                            member = User.objects.get(id=member_id)
                            
                            # Check if the officer is trying to update attendance for a member outside their council
                            if request.user.role == 'officer' and member.council != request.user.council:
                                continue
                                
                            attendance, created = EventAttendance.objects.update_or_create(
                                event=event,
                                member=member,
                                defaults={
                                    'is_present': True,
                                    'recorded_by': request.user
                                }
                            )
                        except User.DoesNotExist:
                            continue
                
                # Get updated count
                present_count = EventAttendance.objects.filter(event=event, is_present=True).count()
                
                # Calculate total count based on user role and event type
                if event.is_global:
                    if request.user.role == 'admin':
                        total_count = User.objects.filter(role='member', is_active=True, is_archived=False).count()
                    else:
                        total_count = User.objects.filter(council=request.user.council, role='member', is_active=True, is_archived=False).count()
                else:
                    total_count = User.objects.filter(council=event.council, role='member', is_active=True, is_archived=False).count()
                
                return JsonResponse({
                    'status': 'success',
                    'present_count': present_count,
                    'total_count': total_count
                })
            except Event.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Event not found'}, status=404)
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
            
        else:
            # Individual update
            member_id = data.get('member_id')
            is_present = data.get('is_present')
            
            # Validate input
            if not event_id or not member_id:
                return JsonResponse({'status': 'error', 'message': 'Missing required fields'}, status=400)
            
            try:
                # Get event and member
                event = get_object_or_404(Event, id=event_id)
                member = get_object_or_404(User, id=member_id)
                
                # Check if the event is approved
                if event.status != 'approved':
                    return JsonResponse({'status': 'error', 'message': 'Can only update attendance for approved events'}, status=400)
                
                # Check if the officer belongs to the event's council
                if request.user.role == 'officer' and event.council != request.user.council and not event.is_global:
                    return JsonResponse({'status': 'error', 'message': 'You can only manage attendance for events in your council'}, status=403)
                
                # Check if the officer is trying to update attendance for a member outside their council
                if request.user.role == 'officer' and member.council != request.user.council:
                    return JsonResponse({'status': 'error', 'message': 'You can only manage attendance for members in your council'}, status=403)
                
                # For testing purposes, bypass the date check
                # Check if the event is happening today
                today = date.today()
                if not (event.date_from <= today <= (event.date_until or event.date_from)):
                    # Temporarily comment out this check for testing
                    # return JsonResponse({'status': 'error', 'message': 'Can only update attendance on the day of the event'}, status=400)
                    pass
                
                # Update or create attendance record
                attendance, created = EventAttendance.objects.update_or_create(
                    event=event,
                    member=member,
                    defaults={
                        'is_present': is_present,
                        'recorded_by': request.user
                    }
                )
                
                # Get updated count
                present_count = EventAttendance.objects.filter(event=event, is_present=True).count()
                
                # Calculate total count based on user role and event type
                if event.is_global:
                    if request.user.role == 'admin':
                        total_count = User.objects.filter(role='member', is_active=True, is_archived=False).count()
                    else:
                        total_count = User.objects.filter(council=request.user.council, role='member', is_active=True, is_archived=False).count()
                else:
                    total_count = User.objects.filter(council=event.council, role='member', is_active=True, is_archived=False).count()
                
                return JsonResponse({
                    'status': 'success',
                    'present_count': present_count,
                    'total_count': total_count,
                    'is_present': is_present
                })
            except Event.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Event not found'}, status=404)
            except User.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Member not found'}, status=404)
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
            
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': f'Unexpected error: {str(e)}'}, status=500)

@never_cache
@login_required
def member_activities(request):
    """View for displaying a member's activities"""
    if request.user.role not in ['member', 'officer', 'admin']:
        return redirect('dashboard')
    
    # Get the member
    member_id = request.GET.get('member_id')
    if member_id and request.user.role in ['admin', 'officer']:
        # Admins and officers can view any member's activities
        member = get_object_or_404(User, id=member_id)
        # Officers can only view members in their council
        if request.user.role == 'officer' and member.council != request.user.council:
            messages.error(request, 'You can only view activities for members in your council.')
            return redirect('dashboard')
    else:
        # Members can only view their own activities
        member = request.user
    
    # Get the member's activities (events they attended)
    activities = EventAttendance.objects.filter(member=member, is_present=True).order_by('-event__date_from')
    
    context = {
        'member': member,
        'activities': activities,
        'is_self': member == request.user
    }
    
    return render(request, 'member_activities.html', context)

@never_cache
def search_members(request):
    """API endpoint for searching members for recruiter autocomplete"""
    query = request.GET.get('q', '')
    if not query or len(query) < 2:
        return JsonResponse({'members': []})
    
    # Search for active members (not pending or archived)
    members = User.objects.filter(
        Q(first_name__icontains=query) | 
        Q(last_name__icontains=query),
        is_archived=False,
        role__in=['member', 'officer', 'admin']
    ).select_related('council')[:10]  # Limit to 10 results
    
    results = [
        {
            'id': member.id,
            'first_name': member.first_name,
            'last_name': member.last_name,
            'full_name': f"{member.first_name} {member.last_name}",
            'council_name': member.council.name if member.council else None
        }
        for member in members
    ]
    
    return JsonResponse({'members': results})

def check_username(request):
    """API endpoint to check if a username already exists"""
    username = request.GET.get('username', '')
    if not username:
        return JsonResponse({'exists': False})
    
    exists = User.objects.filter(username=username, is_archived=False).exists()
    return JsonResponse({'exists': exists})

def check_email(request):
    """API endpoint to check if an email already exists"""
    email = request.GET.get('email', '')
    if not email:
        return JsonResponse({'exists': False})
    
    exists = User.objects.filter(email=email, is_archived=False).exists()
    return JsonResponse({'exists': exists})

def check_for_degree_promotion(user):
    """
    Check if a user should be promoted to the next degree based on recruitment criteria
    
    This is a wrapper around recalculate_degree for backward compatibility
    """
    return recalculate_degree(user)

@never_cache
@login_required
def my_recruits(request):
    """View for displaying a user's recruits"""
    from django.utils import timezone
    from datetime import timedelta
    
    user = request.user
    
    # Get all recruitments by this user
    recruitments = Recruitment.objects.filter(recruiter=user).select_related('recruited').order_by('-date_recruited')
    
    # Get statistics
    total_recruits = recruitments.count()
    
    # Get recent recruitments (within the last month)
    one_month_ago = timezone.now().date() - timedelta(days=30)
    recent_recruitments = recruitments.filter(date_recruited__gte=one_month_ago)
    recent_recruits_count = recent_recruitments.count()
    
    # Get next degree requirements
    current_degree = user.current_degree or '1st'
    next_degree = None
    recruits_needed = 0
    needs_event_attendance = False
    
    if current_degree == '1st':
        next_degree = '2nd'
        recruits_needed = max(0, 1 - recent_recruits_count)
        needs_event_attendance = False
    elif current_degree == '2nd':
        next_degree = '3rd'
        recruits_needed = max(0, 3 - total_recruits)
        needs_event_attendance = True
    elif current_degree == '3rd':
        next_degree = '4th'
        recruits_needed = max(0, 5 - total_recruits)
        needs_event_attendance = True
    
    # Check if user has attended recent events
    has_recent_attendance = False
    if needs_event_attendance:
        has_recent_attendance = EventAttendance.objects.filter(
            member=user,
            is_present=True,
            event__date_from__gte=one_month_ago
        ).exists()
    
    context = {
        'recruitments': recruitments,
        'total_recruits': total_recruits,
        'recent_recruits': recent_recruits_count,
        'current_degree': user.get_current_degree_display() if user.current_degree else '1st Degree',
        'next_degree': dict(User.DEGREE_CHOICES).get(next_degree) if next_degree else None,
        'recruits_needed': recruits_needed,
        'needs_event_attendance': needs_event_attendance,
        'has_recent_attendance': has_recent_attendance,
    }
    
    return render(request, 'my_recruits.html', context)

@never_cache
@login_required
def add_recruitment(request):
    """View for manually adding a recruitment record"""
    if request.user.role != 'admin':
        return redirect('dashboard')
        
    if request.method == 'POST':
        from django.utils import timezone
        
        recruiter_id = request.POST.get('recruiter_id')
        recruit_id = request.POST.get('recruit_id')
        
        try:
            recruiter = User.objects.get(id=recruiter_id, is_archived=False)
            recruit = User.objects.get(id=recruit_id, is_archived=False)
            
            # Check if the recruitment record already exists
            existing_recruitment = Recruitment.objects.filter(
                recruiter=recruiter,
                recruited=recruit
            ).first()
            
            if existing_recruitment:
                messages.warning(request, f'Recruitment record already exists for {recruiter.first_name} {recruiter.last_name} and {recruit.first_name} {recruit.last_name}.')
            else:
                # Create the recruitment record
                recruitment = Recruitment.objects.create(
                    recruiter=recruiter,
                    recruited=recruit,
                    date_recruited=timezone.now().date(),
                    is_manual=True,  # Mark as manually added
                    added_by=request.user  # Record who added it
                )
                
                # Recalculate the recruiter's degree
                recalculate_degree(recruiter)
                
                messages.success(request, f'Recruitment record created: {recruiter.first_name} {recruiter.last_name} recruited {recruit.first_name} {recruit.last_name}.')
        except User.DoesNotExist:
            messages.error(request, 'One or both users not found.')
        except Exception as e:
            messages.error(request, f'Error creating recruitment record: {str(e)}')
    
    # Get all active members (not pending or archived)
    users = User.objects.filter(
        is_archived=False,
        role__in=['member', 'officer', 'admin']
    ).order_by('first_name', 'last_name')
    
    # Get all recruitment records
    all_recruitments = Recruitment.objects.all().select_related('recruiter', 'recruited').order_by('-date_recruited')
    
    return render(request, 'add_recruitment.html', {
        'users': users,
        'all_recruitments': all_recruitments
    })

@never_cache
@login_required
def undo_recruitment(request, history_id):
    """View for undoing a recruitment change"""
    if request.user.role != 'admin':
        return redirect('dashboard')
    
    recruitment = get_object_or_404(Recruitment, id=history_id)
    
    # Only allow undoing manual recruitments added by this admin
    if not recruitment.is_manual or recruitment.added_by != request.user:
        messages.error(request, "You can only undo recruitment records that you manually added.")
        return redirect('add_recruitment')
    
    if request.method == 'POST':
        try:
            recruiter = recruitment.recruiter
            recruiter_name = f"{recruiter.first_name} {recruiter.last_name}"
            recruit_name = f"{recruitment.recruited.first_name} {recruitment.recruited.last_name}"
            
            # Delete the recruitment record
            recruitment.delete()
            
            # Recalculate the recruiter's degree
            recalculate_degree(recruiter)
            
            messages.success(request, f'Recruitment record removed: {recruiter_name} recruiting {recruit_name}.')
        except Exception as e:
            messages.error(request, f'Error undoing recruitment record: {str(e)}')
    
    return redirect('add_recruitment')

@never_cache
@login_required
def change_council(request, user_id):
    """View for changing a member's council"""
    # Only admins and officers can change councils
    if request.user.role not in ['admin', 'officer']:
        messages.error(request, 'You do not have permission to change council assignments.')
        return redirect('dashboard')
    
    # Get the user
    user_to_change = get_object_or_404(User, id=user_id)
    
    # Admin can change council for any user
    # Officer can only change council for members in their council
    if request.user.role == 'officer':
        # Officers can only change members (not officers or admins)
        if user_to_change.role != 'member':
            messages.error(request, 'Officers can only change council for members, not for officers or admins.')
            return redirect('council_members')
            
        # Officers can only change members in their own council
        if user_to_change.council != request.user.council:
            messages.error(request, 'You can only change council for members in your council.')
            return redirect('council_members')
    
    # Get all councils
    councils = Council.objects.all()
    
    if request.method == 'POST':
        new_council_id = request.POST.get('council')
        
        try:
            new_council = Council.objects.get(id=new_council_id)
            
            # Update the user's council
            user_to_change.council = new_council
            user_to_change.save()
            
            messages.success(request, f'{user_to_change.first_name} {user_to_change.last_name} has been moved to {new_council.name}.')
            
            # Redirect based on user role
            if request.user.role == 'admin':
                return redirect('member_list')
            else:
                return redirect('council_members')
                
        except Council.DoesNotExist:
            messages.error(request, 'The selected council does not exist.')
    
    context = {
        'user_to_change': user_to_change,
        'councils': councils
    }
    
    return render(request, 'change_council.html', context)

logger = logging.getLogger(__name__)
def capstone_project(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('message')

        if not all([name, email, message]):
            return render(request, 'homepage.html', {'error': 'All fields are required.'})

        try:
            send_mail(
                subject=f'Contact Us Message from {name}',
                message=f'Name: {name}\nEmail: {email}\nMessage: {message}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=['cratoscms@gmail.com'],
                fail_silently=False,
            )
            logger.info(f"Contact form email sent from {email} to cratoscms@gmail.com")
            return render(request, 'homepage.html', {'success': 'Your message has been sent successfully!'})
        except Exception as e:
            logger.error(f"Failed to send contact form email: {str(e)}")
            return render(request, 'homepage.html', {'error': 'Failed to send message. Please try again.'})

    return render(request, 'homepage.html')

def recalculate_degree(user):
    """
    Recalculate a user's degree based on their recruitment records
    
    Will promote or demote the user based on the current recruitment criteria:
    * 1st Degree: Default
    * 2nd Degree: 1-2 recruits (no longer than 1 month)
    * 3rd Degree: 3-4 recruits (even the past recruits/cumulative) attended recent events (no longer than 1 month)
    * 4th Degree: 5+ recruits (even the past recruits/cumulative) attended recent events (no longer than 1 month)
    """
    from django.utils import timezone
    from datetime import timedelta
    
    if not user or user.is_archived:
        print(f"Skipping degree recalculation for invalid or archived user")
        return False
    
    print(f"Recalculating degree for user {user.username} (current: {user.current_degree or '1st'})")
    
    # Get all recruitments by this user
    recruitments = Recruitment.objects.filter(recruiter=user)
    total_recruits = recruitments.count()
    
    # Get recent recruitments (within the last month)
    one_month_ago = timezone.now().date() - timedelta(days=30)
    recent_recruitments = recruitments.filter(date_recruited__gte=one_month_ago)
    recent_recruits_count = recent_recruitments.count()
    
    # Get recent event attendance
    recent_events_attended = EventAttendance.objects.filter(
        member=user,
        is_present=True,
        event__date_from__gte=one_month_ago
    ).count()
    
    print(f"User {user.username}: Total recruits: {total_recruits}, Recent recruits: {recent_recruits_count}, Recent events attended: {recent_events_attended}")
    
    # Store the original degree for comparison
    original_degree = user.current_degree or '1st'
    
    # Determine the appropriate degree based on criteria
    if total_recruits >= 5 and recent_events_attended > 0:
        new_degree = '4th'
    elif total_recruits >= 3 and recent_events_attended > 0:
        new_degree = '3rd'
    elif recent_recruits_count >= 1:
        new_degree = '2nd'
    else:
        new_degree = '1st'
    
    print(f"User {user.username}: Calculated appropriate degree: {new_degree}")
    
    # Degree rank mapping for proper comparison
    degree_rank = {
        '1st': 1,
        '2nd': 2,
        '3rd': 3,
        '4th': 4
    }
    
    # Update the user's degree if it has changed
    if new_degree != original_degree:
        user.current_degree = new_degree
        user.save()
        print(f"User {user.username}: Degree updated from {original_degree} to {new_degree}")
        
        # Create a notification for the user about their degree change
        try:
            if degree_rank[new_degree] > degree_rank[original_degree]:
                # Promotion
                Notification.objects.create(
                    user=user,
                    title=f"Congratulations! You've been promoted to {user.get_current_degree_display()}",
                    content=f"Your dedication to the Knights of Columbus has earned you a promotion to {user.get_current_degree_display()}.",
                    is_read=False
                )
                print(f"User {user.username}: Promotion notification created")
            else:
                # Demotion
                Notification.objects.create(
                    user=user,
                    title=f"Your degree has been updated to {user.get_current_degree_display()}",
                    content=f"Due to changes in your recruitment history, your degree has been updated to {user.get_current_degree_display()}.",
                    is_read=False
                )
                print(f"User {user.username}: Demotion notification created")
        except Exception as e:
            print(f"Error creating degree change notification: {str(e)}")
    
    return True
