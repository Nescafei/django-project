from .models import User, Council, Event, Analytics, Donation, Blockchain, blockchain, Block
from django.contrib.auth.decorators import login_required, permission_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
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
from django.dispatch import receiver
from django.conf import settings
from django.urls import reverse
from io import BytesIO
from datetime import datetime, date
from base64 import b64encode, b64decode
import base64
import os
import re
import uuid
import logging
import requests
import json

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
    return render(request, 'councils.html')

def donation_page(request):
    if request.method == 'POST':
        return render(request, 'donation_form.html', {
            'error': 'Form submission failed. Please try again.'
        })
    return render(request, 'donation_form.html')

@never_cache
def sign_in(request):
    if request.user.is_authenticated:
        logger.debug(f"User {request.user.username} already authenticated, redirecting to dashboard")
        return redirect('dashboard')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        logger.debug(f"Attempting to authenticate user: {username}")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            if user.is_active and not user.is_archived:
                if user.role == 'pending':
                    pending_message = 'Your account is pending approval. Please wait for an officer to review your request.'
                    logger.debug(f"User {username} is pending approval")
                    return render(request, 'sign-in.html', {'pending_message': pending_message})
                else:
                    login(request, user)
                    logger.debug(f"User {username} logged in successfully, role: {user.role}, redirecting to dashboard")
                    return redirect('dashboard')
            else:
                logger.debug(f"User {username} is not active or is archived")
                return render(request, 'sign-in.html', {'error': 'This account is not active or has been archived'})
        else:
            logger.debug(f"Authentication failed for username: {username}")
            return render(request, 'sign-in.html', {'error': 'Invalid username or password'})
    logger.debug("Rendering sign-in page")
    return render(request, 'sign-in.html')

@never_cache
def sign_up(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    councils = Council.objects.all()
    logger.debug(f"Number of councils available: {councils.count()}")
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
        logger.debug(f"Received form data: full_name={full_name}, username={username}, email={email}, council_id={council_id}")

        if password != re_password:
            logger.debug("Validation failed: Passwords do not match")
            return render(request, 'sign-up.html', {'error': 'Passwords do not match', 'councils': councils})

        if not username:
            logger.debug("Validation failed: Username is required")
            return render(request, 'sign-up.html', {'error': 'Username is required', 'councils': councils})

        if User.objects.filter(username=username, is_archived=False).exists():
            logger.debug(f"Validation failed: Username {username} already exists")
            return render(request, 'sign-up.html', {'error': 'This username is already taken', 'councils': councils})

        try:
            birth_date = datetime.strptime(birthday, '%Y-%m-%d').date()
            today = datetime.today().date()
            age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
            if age < 18:
                logger.debug("Validation failed: User must be at least 18 years old")
                return render(request, 'sign-up.html', {'error': 'You must be at least 18 years old to sign up', 'councils': councils})
        except ValueError:
            logger.debug("Validation failed: Invalid birthday format")
            return render(request, 'sign-up.html', {'error': 'Invalid birthday format', 'councils': councils})

        try:
            council = Council.objects.get(id=council_id) if council_id else None
            if not council and council_id:
                logger.debug("Validation failed: Invalid council selected")
                return render(request, 'sign-up.html', {'error': 'Invalid council selected', 'councils': councils})
        except Council.DoesNotExist:
            logger.debug("Validation failed: Council does not exist")
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
            logger.info(f"User {username} saved successfully with role={user.role}, council={council}")
            success_message = 'Account request submitted. Awaiting approval. Use your username to sign in once approved.'
            return render(request, 'sign-up.html', {'success': success_message, 'councils': councils})
        except Exception as e:
            logger.error(f"Sign Up Error: {str(e)}")
            return render(request, 'sign-up.html', {'error': f'An error occurred during registration: {str(e)}', 'councils': councils})
    return render(request, 'sign-up.html', {'councils': councils})

def logout_view(request):
    logout(request)
    logger.debug("User logged out")
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
        logger.debug(f"User {user.username} is pending, redirecting to sign-in")
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
            return redirect('dashboard')
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
        pending_users = User.objects.filter(
            role='pending',
            council=request.user.council,
            is_archived=False
        )
    elif request.user.role == 'admin':
        pending_users = User.objects.filter(role='pending', is_archived=False)
    else:
        pending_users = User.objects.none()
    
    logger.debug(f"Pending users for {request.user.username} (role={request.user.role}): {pending_users.count()}")
    for user in pending_users:
        logger.debug(f"User ID={user.id}, Username={user.username}, Council={user.council.name if user.council else 'None'}")
    
    return render(request, 'manage_pending_users.html', {'pending_users': pending_users})

@never_cache
@login_required
def approve_user(request, user_id):
    if request.user.role not in ['officer', 'admin']:
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id, is_archived=False)
    if user.council == request.user.council or request.user.role == 'admin':
        user.role = 'member'
        user.save()
        logger.info(f"User {user.username} approved by {request.user.username}")
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
        logger.info(f"User {user.username} archived by {request.user.username}")
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
        logger.debug(f"User {request.user.username} attempted to archive themselves")
        return redirect('dashboard')
    user.is_active = False
    user.is_archived = True
    user.save()
    logger.info(f"User {user.username} archived by {request.user.username}")
    return redirect('dashboard')

@never_cache
@login_required
def archived_users(request):
    if request.user.role != 'admin':
        return redirect('dashboard')
    archived_users = User.objects.filter(is_archived=True)
    logger.debug(f"Admin {request.user.username} accessed archived users: {archived_users.count()} found")
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
    if request.user.role == 'officer' and (user.role != 'member' or user.council != request.user.council):
        return redirect('dashboard')
    if request.method == 'POST':
        degree = request.POST.get('current_degree')
        logger.debug(f"Received degree: {degree}")
        valid_degrees = [choice[0] for choice in User._meta.get_field('current_degree').choices]
        logger.debug(f"Valid degrees: {valid_degrees}")
        if degree in valid_degrees:
            user.current_degree = degree
            user.save()
            logger.info(f"User {user.username}'s degree updated to {degree} by {request.user.username}")
        else:
            logger.error(f"Invalid degree {degree} selected for user {user.username}")
        return redirect('dashboard')
    return render(request, 'update_degree.html', {'user': user})

@never_cache
@login_required
def edit_profile(request):
    user = request.user
    if request.method == 'POST':
        try:
            user.first_name = request.POST.get('first_name', user.first_name)
            user.last_name = request.POST.get('last_name', user.last_name)
            user.username = request.POST.get('username', user.username)
            user.address = request.POST.get('address', user.address)
            user.contact_number = request.POST.get('contact_number', user.contact_number)

            password = request.POST.get('password')
            if password:
                user.set_password(password)

            cropped_image = request.POST.get('cropped_image')
            if cropped_image:
                format, imgstr = re.match(r'data:image/(\w+);base64,(.+)', cropped_image).groups()
                image_data = b64decode(imgstr)
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
@permission_required('capstone_project.add_manual_donation', raise_exception=True)
def manual_donation(request):
    if request.method == 'POST':
        logger.debug(f"POST data: {dict(request.POST)}")
        form = ManualDonationForm(request.POST, request.FILES)
        if form.is_valid():
            donation = form.save(commit=False)
            donation.payment_method = 'manual'
            donation.submitted_by = request.user
            donation.transaction_id = f"MANUAL-{uuid.uuid4().hex[:8]}"
            donation.source_id = ''
            donation.status = 'pending_manual'
            donation.save()
            logger.info(f"Manual donation created: ID={donation.id}, Email={donation.email}, Amount={donation.amount}, Status={donation.status}")
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
@permission_required('capstone_project.review_manual_donations', raise_exception=True)
def review_manual_donations(request):
    if request.user.role == 'admin':
        pending_donations = Donation.objects.filter(status='pending_manual')
    else:
        pending_donations = Donation.objects.filter(status='pending_manual').exclude(submitted_by=request.user)
    
    logger.debug(f"User {request.user.username} (role={request.user.role}, council={request.user.council.name if request.user.council else 'None'}): Found {pending_donations.count()} pending manual donations")
    for donation in pending_donations:
        logger.debug(f"Donation ID={donation.id}, Transaction={donation.transaction_id}, Submitted by={donation.submitted_by.username if donation.submitted_by else 'None'}, Council={donation.submitted_by.council.name if donation.submitted_by and donation.submitted_by.council else 'None'}")
    
    paginator = Paginator(pending_donations, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.method == 'POST':
        donation_id = request.POST.get('donation_id')
        action = request.POST.get('action')
        rejection_reason = request.POST.get('rejection_reason', '')

        try:
            donation = Donation.objects.get(id=donation_id, status='pending_manual')
            if request.user.role == 'officer' and donation.submitted_by and donation.submitted_by.council and donation.submitted_by.council != request.user.council:
                messages.error(request, 'You are not authorized to review this donation.')
                return redirect('review_manual_donations')
            if donation.submitted_by == request.user:
                messages.error(request, 'You cannot review your own donation.')
                return redirect('review_manual_donations')

            with transaction.atomic():
                if action == 'approve':
                    donation.status = 'completed'
                    donation.reviewed_by = request.user
                    donation.sign_donation(PRIVATE_KEY)
                    donation.save()
                    blockchain.initialize_chain()
                    transaction = blockchain.add_transaction(donation, PUBLIC_KEY)
                    if transaction:
                        previous_block = blockchain.get_previous_block()
                        previous_proof = previous_block['proof']
                        proof = blockchain.proof_of_work(previous_proof)
                        new_block = blockchain.create_block(proof)
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
            messages.error(request, 'Donation not found or already reviewed.')
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