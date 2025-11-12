import base64, os, uuid, logging, requests
from capstone_project.forms import DonationForm, ManualDonationForm
from capstone_project.models import User, Council, Event, Analytics, Donation, Blockchain, blockchain, Block, ForumCategory, ForumMessage, Notification, EventAttendance, Recruitment, get_blockchain
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, date
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models.signals import pre_save, pre_delete
from django.dispatch import receiver
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.urls import reverse

PRIVATE_KEY = getattr(settings, 'PRIVATE_KEY', None)
PUBLIC_KEY = getattr(settings, 'PUBLIC_KEY', None)

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

# Updated donations view in donation.py
@never_cache
def donations(request):
    show_manual_link = request.user.is_authenticated and request.user.role in ['admin', 'officer']
    logger.debug(f"show_manual_link: {show_manual_link}, User: {request.user}, Role: {getattr(request.user, 'role', 'N/A')}")
    if request.method == 'POST':
        form = DonationForm(request.POST, request.FILES)
        logger.debug(f"Form fields: {form.as_p()}")
        if form.is_valid():
            donation = form.save(commit=False)  # Event is now included via form
            donation.submitted_by = request.user if request.user.is_authenticated else None
            donation.transaction_id = f"GCASH-{uuid.uuid4().hex[:8]}"
            donation.payment_method = 'gcash'
            donation.status = 'pending'
            donation.signature = ''
            donation.donation_date = date.today()
            donation.save()
            logger.info(f"GCash donation created: ID={donation.id}, Email={donation.email}, Amount={donation.amount}, Event={donation.event.name if donation.event else 'General'}")
            return initiate_gcash_payment(request, donation)
        else:
            logger.debug(f"Form errors: {form.errors}")
            messages.error(request, 'Please correct the errors in the form.')
    else:
        from django.db.models import Q
        from datetime import date
        today = date.today()
        upcoming_events = Event.objects.filter(
            Q(date_from__gte=today) | Q(date_until__gte=today),
            status='approved'
        ).order_by('date_from')
        form = DonationForm()
        form.fields['event'].queryset = upcoming_events
        logger.debug(f"Rendered form HTML: {form.as_p()}")
    return render(request, 'donations.html', {'form': form, 'show_manual_link': show_manual_link})

@csrf_protect
@login_required
def manual_donation(request):
    if request.method == 'POST':
        logger.debug(f"POST data: {dict(request.POST)}")
        form = ManualDonationForm(request.POST, request.FILES)
        if form.is_valid():
            donation = form.save(commit=False)  # Event is now included via form
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
            donation.donation_date = date.today()
            donation.save()
            logger.info(f"Manual donation created: ID={donation.id}, Email={donation.email or 'Anonymous'}, Amount={donation.amount}, Status={donation.status}, Council={donation.council.name if donation.council else 'None'}, Event={donation.event.name if donation.event else 'General'}")
            messages.success(request, 'Manual donation submitted for review.')
            return redirect('donations')
        else:
            logger.debug(f"Form errors: {form.errors}")
            messages.error(request, 'Please correct the errors in the form.')
    else:
        from django.db.models import Q
        from datetime import date
        today = date.today()
        upcoming_events = Event.objects.filter(
            Q(date_from__gte=today) | Q(date_until__gte=today),
            status='approved'
        ).order_by('date_from')
        form = ManualDonationForm()
        form.fields['event'].queryset = upcoming_events
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
                    blockchain.initialize_chain()
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
                    logger.debug(f"Previous proof: {previous_proof}")
                    proof = blockchain.proof_of_work(previous_proof)
                    logger.debug(f"Proof of work completed: {proof}")
                    new_block = blockchain.create_block(proof)
                    logger.debug(f"New block created: {new_block}")
                    if new_block:
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