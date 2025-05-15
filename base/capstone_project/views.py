from capstone_project.models import User, Council, Event, Analytics, Donation, blockchain
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.contrib.sessions.models import Session
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.paginator import Paginator
from django.urls import reverse
from django.conf import settings
from django.template.loader import render_to_string
from paypal.standard.forms import PayPalPaymentsForm
from paypal.standard.models import ST_PP_COMPLETED
from paypal.standard.ipn.signals import valid_ipn_received
import base64
from io import BytesIO
import os
import re
from datetime import datetime
import uuid
import logging
import requests
import json
from decimal import Decimal

# Set up logging
logger = logging.getLogger(__name__)

# PayMongo API base URL
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

def donations(request):
    if request.method == 'POST':
        amount = request.POST.get('amount')
        name = request.POST.get('name')
        email = request.POST.get('email')
        print(f"Donation Form Submitted: Amount=₱{amount}, Name={name}, Email={email}")
        
        # Create donation record
        donation = Donation(
            donor_name=name,
            donor_email=email,
            amount=amount,
            payment_method='online',
            status='pending',
            transaction_id=f'ONLINE-{uuid.uuid4().hex[:8]}',
            submitted_by=request.user if request.user.is_authenticated else None
        )
        donation.save()
        print(f"Online Donation created: ID={donation.id}, Transaction ID={donation.transaction_id}")
        return HttpResponseRedirect('/donations/')
    
    # Show manual donation link only for officers and admins
    show_manual_link = request.user.is_authenticated and request.user.role in ['officer', 'admin']
    return render(request, 'donations.html', {'show_manual_link': show_manual_link})

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

@never_cache
@login_required
def manual_donation_input(request):
    if request.user.role not in ['officer', 'admin']:
        print(f"User {request.user.username} (role: {request.user.role}) not authorized for manual donation input")
        return redirect('donations')
    
    if request.method == 'POST':
        donor_name = request.POST.get('donor_name')
        donor_email = request.POST.get('donor_email')
        amount_str = request.POST.get('amount')
        donation_date_str = request.POST.get('donation_date')
        notes = request.POST.get('notes', '')
        receipt = request.FILES.get('receipt')

        # Validation
        if not donor_name:
            return render(request, 'manual_donation.html', {'error': 'Donor name is required.'})
        if not donor_email:
            return render(request, 'manual_donation.html', {'error': 'Donor email is required.'})
        try:
            amount = float(amount_str)
            if amount <= 0:
                return render(request, 'manual_donation.html', {'error': 'Amount must be greater than 0.'})
        except (ValueError, TypeError):
            return render(request, 'manual_donation.html', {'error': 'Invalid amount format.'})
        try:
            donation_date = datetime.strptime(donation_date_str, '%Y-%m-%d').date() if donation_date_str else None
            if donation_date and donation_date > datetime.now().date():
                return render(request, 'manual_donation.html', {'error': 'Donation date cannot be in the future.'})
        except ValueError:
            return render(request, 'manual_donation.html', {'error': 'Invalid date format. Use YYYY-MM-DD.'})

        # Create Donation
        donation = Donation.objects.create(
            donor_name=donor_name,
            donor_email=donor_email,
            amount=amount,
            payment_method='manual',
            status='pending_manual',
            transaction_id=f'MANUAL-{uuid.uuid4().hex[:8]}',
            donation_date=donation_date,
            receipt=receipt,
            notes=notes,
            submitted_by=request.user
        )
        logger.info(f"Manual Donation created: ID={donation.id}, Transaction ID={donation.transaction_id}, Donor Email={donor_email}, Amount={amount}, Date={donation_date}, Notes={notes}, Receipt={receipt}")
        messages.success(request, 'Manual donation submitted for review. Awaiting approval.')
        return redirect('donations')

    return render(request, 'manual_donation.html')

@never_cache
@login_required
def review_manual_donations(request):
    if request.user.role not in ['officer', 'admin']:
        print(f"User {request.user.username} (role: {request.user.role}) not authorized for manual donation review")
        return redirect('dashboard')

    if request.method == 'POST':
        donation_id = request.POST.get('donation_id')
        action = request.POST.get('action')

        try:
            donation = Donation.objects.get(id=donation_id, status='pending_manual')
            # Officers can only review donations submitted by users in their council
            if request.user.role == 'officer' and donation.submitted_by.council != request.user.council:
                messages.error(request, 'You are not authorized to review this donation.')
                return redirect('review_manual_donations')

            if action == 'approve':
                donation.status = 'completed'
                block_index = blockchain.add_block(donation)  # Add block
                if block_index is not None:
                    donation.block_index = block_index  # Set block_index
                donation.save()
                logger.info(f"Manual Donation {donation.id} approved by {request.user.username}, block_index={block_index}")
                messages.success(request, f"Donation {donation.id} approved successfully.")
            elif action == 'reject':
                donation.status = 'failed'
                donation.save()
                logger.info(f"Manual Donation {donation.id} rejected by {request.user.username}")
                messages.success(request, f"Donation {donation.id} rejected.")
            else:
                messages.error(request, 'Invalid action.')
        except Donation.DoesNotExist:
            messages.error(request, 'Donation not found or already reviewed.')

        return redirect('review_manual_donations')

    # Filter donations based on role
    if request.user.role == 'admin':
        pending_donations = Donation.objects.filter(status='pending_manual')
    else:  # Officer
        pending_donations = Donation.objects.filter(status='pending_manual', submitted_by__council=request.user.council)
    return render(request, 'review_manual_donations.html', {'donations': pending_donations})

@csrf_exempt
def initiate_paypal_payment(request):
    if request.method != 'POST':
        logger.error("PayPal Error: Invalid request method")
        return JsonResponse({'error': 'Invalid request method'}, status=400)

    try:
        # Handle JSON or form-data
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            amount_str = data.get('amount')
            donor_email = data.get('donor_email')
        else:
            amount_str = request.POST.get('amount')
            donor_email = request.POST.get('donor_email')

        if not amount_str:
            raise ValidationError("Amount is required")
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValidationError("Amount must be greater than 0")
        except (ValueError, TypeError):
            raise ValidationError("Invalid amount format")

        if not donor_email:
            raise ValidationError("Donor email is required")

        # Create Donation record
        try:
            donation = Donation(
                donor_email=donor_email,
                amount=Decimal(amount_str).quantize(Decimal('0.01')),
                payment_method='paypal',
                transaction_id=f'PENDING-PP-{uuid.uuid4().hex[:8]}',
            )
            donation.save()
            logger.info(f"Donation created: ID={donation.id}, Transaction ID={donation.transaction_id}")
        except Exception as e:
            logger.error(f"Failed to create Donation: {str(e)}")
            raise ValidationError(f"Failed to create donation: {str(e)}")

        # PayPal form
        paypal_dict = {
            'business': settings.PAYPAL_RECEIVER_EMAIL,
            'amount': str(amount),
            'item_name': 'Donation',
            'invoice': donation.transaction_id,
            'notify_url': request.build_absolute_uri(reverse('paypal-ipn')),
            'return': request.build_absolute_uri('/success/'),
            'cancel_return': request.build_absolute_uri('/cancel/'),
            'custom': str(donation.id),
            'currency_code': 'USD',
        }
        form = PayPalPaymentsForm(initial=paypal_dict)
        form_html = render_to_string('paypal_form.html', {'form': form})
        response = {
            'form': form_html
        }
        logger.info(f"PayPal Dict: {paypal_dict}")
        logger.info(f"PayPal Initiate Response: {response}, Redirect URLs: return={paypal_dict.get('return', 'N/A')}, cancel={paypal_dict.get('cancel_return', 'N/A')}")
        return JsonResponse(response)
    except ValidationError as e:
        logger.error(f"PayPal Error: {str(e)}")
        return JsonResponse({'error': str(e)}, status=400)
    except json.JSONDecodeError:
        logger.error("PayPal Error: Invalid JSON data")
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        logger.error(f"Unexpected PayPal Error: {str(e)}")
        return JsonResponse({'error': f"Unexpected error: {str(e)}"}, status=500)

@csrf_exempt
def initiate_gcash_payment(request):
    if request.method != 'POST':
        logger.error("GCash: Invalid request method")
        return JsonResponse({'error': 'Invalid request method'}, status=400)

    try:
        donor_email = request.POST.get('donor_email')
        if not donor_email:
            logger.error("GCash: Donor email is required")
            return JsonResponse({'error': 'Donor email is required'}, status=400)
        amount_str = request.POST.get('amount')
        if not amount_str:
            logger.error("GCash: Amount is required")
            return JsonResponse({'error': 'Amount is required'}, status=400)
        try:
            amount = float(amount_str) * 100  # Convert to centavos
            if amount <= 0:
                logger.error("GCash: Amount must be greater than 0")
                return JsonResponse({'error': 'Amount must be greater than 0'}, status=400)
        except (ValueError, TypeError):
            logger.error("GCash: Invalid amount format")
            return JsonResponse({'error': 'Invalid amount format'}, status=400)

        payment_method = 'gcash'
        donation = Donation.objects.create(
            donor_email=donor_email,
            amount=Decimal(amount / 100).quantize(Decimal('0.01')),
            payment_method=payment_method,
            status='pending',
            transaction_id=f'PENDING-GC-{uuid.uuid4().hex[:8]}',
            source_id=''  # Will be updated after source creation
        )
        logger.info(f"Donation created: ID={donation.id}, Transaction ID={donation.transaction_id}, Donor Email={donor_email}")

        # PayMongo API request
        auth_key = base64.b64encode(f"{settings.PAYMONGO_SECRET_KEY}:".encode()).decode()
        headers = {'Authorization': f'Basic {auth_key}'}        # Include source_id in the success URL
        payload = {
            'data': {
                'attributes': {
                    'type': 'gcash',
                    'amount': int(amount),
                    'currency': 'PHP',
                    'description': 'Donation via GCash',
                    'redirect': {
                        'success': request.build_absolute_uri(f"/gcash/confirm/?donation_id={donation.id}"),
                        'failed': request.build_absolute_uri('/cancel/')
                    },
                    'metadata': {
                        'donation_id': str(donation.id),
                        'source_id': '',
                    }
                }
            }
        }
        logger.info(f"GCash Request: URL={PAYMONGO_API_URL}/sources, Headers=Authorization: Basic [REDACTED], Payload={payload}")

        response = requests.post(f'{PAYMONGO_API_URL}/sources', headers=headers, json=payload)
        logger.info(f"GCash Raw Response: Status={response.status_code}, Text={response.text}")
        if response.status_code != 200:
            error_detail = response.text
            logger.error(f"GCash: PayMongo API error: Status={response.status_code}, Detail={error_detail}")
            return JsonResponse({'error': f'PayMongo API error: {error_detail}'}, status=500)
        source = response.json()['data']
        logger.info(f"GCash Parsed Response: Source={source}")
        source_id = source.get('id')
        if not source_id:
            logger.error(f"GCash: No 'id' field in source response: {source}")
            return JsonResponse({'error': 'Invalid PayMongo response: No source ID'}, status=500)

        donation.source_id = source_id
        donation.save()
        logger.info(f"GCash Response: Status={response.status_code}, Source ID={source_id}, Full Response={response.json()}")

        return JsonResponse({'redirect_url': source['attributes']['redirect']['checkout_url']})
    except requests.RequestException as e:
        error_msg = f"GCash: PayMongo API request failed: {str(e)}"
        if hasattr(e, 'response') and e.response:
            error_msg += f" (Status: {e.response.status_code}, Detail: {e.response.text})"
        logger.error(error_msg)
        return JsonResponse({'error': error_msg}, status=500)
    except Exception as e:
        logger.error(f"GCash: Unexpected error: {str(e)}")
        return JsonResponse({'error': f'Unexpected error: {str(e)}'}, status=500)
    
@csrf_exempt
def confirm_gcash_payment(request):
    logger.info("Entering confirm_gcash_payment view")
    logger.info(f"Request URL: {request.build_absolute_uri()}")
    logger.info(f"Request GET parameters: {dict(request.GET)}")
    donation_id = request.GET.get('donation_id')
    logger.info(f"GCash: Received confirmation request with donation_id={donation_id}")

    if not donation_id:
        logger.error("GCash: No donation_id provided in request")
        # Fallback: Retrieve the most recent pending GCash donation
        recent_donation = Donation.objects.filter(
            payment_method='gcash',
            status='pending'
        ).order_by('-created_at').first()
        if recent_donation:
            logger.info(f"Found recent donation with ID={recent_donation.id}, attempting to confirm")
            donation = recent_donation
        else:
            logger.error("GCash: Could not infer donation from recent donations")
            return render(request, 'cancel.html', {
                'error': 'Payment confirmation failed: No donation ID provided, and no recent pending GCash donation found. Please try again or contact support.'
            })
    else:
        try:
            donation = Donation.objects.get(id=donation_id, payment_method='gcash', status='pending')
        except Donation.DoesNotExist:
            logger.error(f"GCash: No pending donation found for donation_id={donation_id}")
            return render(request, 'cancel.html', {'error': 'No matching donation found. Please try again or contact support.'})

    source_id = donation.source_id
    if not source_id:
        logger.error(f"GCash: Donation {donation.id} has no source_id")
        return render(request, 'cancel.html', {'error': 'Payment confirmation failed: No source ID associated with this donation.'})

    try:
        # Prevent re-processing if already completed
        if donation.status != 'pending':
            logger.warning(f"Donation {donation.id} already processed with status {donation.status}")
            return render(request, 'success.html', {'message': 'Payment already confirmed!'})

        auth_key = base64.b64encode(f"{settings.PAYMONGO_SECRET_KEY}:".encode()).decode()
        headers = {'Authorization': f'Basic {auth_key}'}
        response = requests.get(f'{PAYMONGO_API_URL}/sources/{source_id}', headers=headers)
        if response.status_code != 200:
            logger.error(f"GCash: PayMongo source verification failed: Status={response.status_code}, Detail={response.text}")
            return render(request, 'cancel.html', {'error': 'Payment verification failed: Invalid source. Please try again or contact support.'})
        source_data = response.json()['data']
        logger.info(f"PayMongo Source Verification Response: {source_data}")

        # Check source status
        source_status = source_data['attributes']['status']
        if source_status != 'chargeable':
            logger.info(f"GCash: Source {source_id} is not yet chargeable, status={source_status}")
            return render(request, 'processing.html', {
                'message': 'Payment is being processed. You will be notified once it is confirmed.'
            })

        payment_id = source_data['attributes'].get('payment_id') or source_id
        donation.status = 'completed'
        donation.transaction_id = payment_id
        block_index = blockchain.add_block(donation)  # Add block once
        if block_index is not None:
            donation.block_index = block_index
        donation.save()
        logger.info(f"GCash: Donation {donation.id} marked as completed, Txn ID: {payment_id}, Donor Email={donation.donor_email}")
        logger.info(f"Block created for Donation {donation.id}, block_index={block_index}")

        return render(request, 'success.html', {'message': 'Payment confirmed successfully!'})
    except requests.RequestException as e:
        logger.error(f"GCash: PayMongo verification failed: {str(e)}", exc_info=True)
        return render(request, 'cancel.html', {'error': f'Payment verification failed: {str(e)}. Please try again or contact support.'})
    except Exception as e:
        logger.error(f"GCash: Unexpected error in confirmation: {str(e)}", exc_info=True)
        return render(request, 'cancel.html', {'error': f'Unexpected error during payment confirmation: {str(e)}. Please contact support.'})
    
def paypal_ipn_handler(sender, **kwargs):
    ipn_obj = sender
    logger.info(f"PayPal IPN: Status={ipn_obj.payment_status}, Invoice={ipn_obj.invoice}, Custom={ipn_obj.custom}, Amount={ipn_obj.mc_gross}, Currency={ipn_obj.mc_currency}")
    if ipn_obj.payment_status == ST_PP_COMPLETED:
        try:
            donation = Donation.objects.get(id=ipn_obj.custom)
            if ipn_obj.mc_currency == 'USD' and abs(float(ipn_obj.mc_gross) - float(donation.amount)) < 0.01:
                donation.transaction_id = ipn_obj.txn_id
                donation.status = 'completed'
                block_index = blockchain.add_block(donation)  # Add block
                if block_index is not None:
                    donation.block_index = block_index  # Set block_index
                donation.save()
                logger.info(f"PayPal IPN: Donation {donation.id} marked as completed, Txn ID: {ipn_obj.txn_id}, block_index={block_index}")
            else:
                logger.error(f"PayPal IPN: Validation failed for Donation {donation.id}: Amount={ipn_obj.mc_gross}, Currency={ipn_obj.mc_currency}, Expected={donation.amount}, USD")
        except Donation.DoesNotExist:
            logger.error(f"PayPal IPN: Donation ID {ipn_obj.custom} not found")
        except Exception as e:
            logger.error(f"PayPal IPN: Unexpected error for Donation ID {ipn_obj.custom}: {str(e)}")
    else:
        try:
            donation = Donation.objects.get(id=ipn_obj.custom)
            donation.status = 'failed'
            donation.save()
            logger.info(f"PayPal IPN: Donation {donation.id} marked as failed")
        except Donation.DoesNotExist:
            logger.error(f"PayPal IPN: Donation ID {ipn_obj.custom} not found")
        except Exception as e:
            logger.error(f"PayPal IPN: Failed to process Donation ID {ipn_obj.custom}: {str(e)}")

valid_ipn_received.connect(paypal_ipn_handler)

@login_required
def get_blockchain_data(request):
    chain = blockchain.get_chain()
    total_amount = 0
    for block in chain:
        for tx in block.get('transactions', []):
            try:
                amount = float(tx.split('Amount: ₱')[1].split(',')[0])
                total_amount += amount
            except (IndexError, ValueError) as e:
                logger.error(f"Error parsing transaction amount: {tx}, {str(e)}")

    # Add pagination
    paginator = Paginator(chain, 10)  # Show 10 blocks per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'blockchain.html', {
        'page_obj': page_obj,  # Pass the paginated object
        'is_valid': blockchain.is_chain_valid(),
        'total_amount': total_amount,
    })

def success_page(request):
    return render(request, 'success.html', {'message': 'Payment processing. Awaiting confirmation.'})

def cancel_page(request):
    return render(request, 'cancel.html', {'error': 'Payment was cancelled or failed.'})