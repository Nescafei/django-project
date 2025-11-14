from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from django.db import models
from django.db.models.signals import pre_save
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.conf import settings
from django.utils import timezone
from django.utils.functional import SimpleLazyObject
from PIL import Image
from datetime import date, datetime
import logging
import hashlib
import base64
import json
import uuid
import os
from decimal import Decimal

logger = logging.getLogger(__name__)

def generate_transaction_id():
    return f"GCASH-{uuid.uuid4().hex[:8]}"

class Council(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=100)
    district = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class User(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('officer', 'Officer'),
        ('member', 'Member'),
        ('pending', 'Pending'),
    )
    DEGREE_CHOICES = [
        ('1st', '1st Degree'),
        ('2nd', '2nd Degree'),
        ('3rd', '3rd Degree'),
        ('4th', '4th Degree'),
    ]
    GENDER_CHOICES = [
        ('Male', 'Male'),
    ]
    RELIGION_CHOICES = [
        ('Catholic', 'Catholic'),
        ('Other', 'Other'),
    ]
    MARITAL_STATUS_CHOICES = [
        ('Single', 'Single'),
        ('Married', 'Married'),
        ('Widowed', 'Widowed'),
        ('Divorced', 'Divorced'),
        ('Separated', 'Separated'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='pending')
    council = models.ForeignKey('Council', on_delete=models.SET_NULL, null=True, blank=True)
    age = models.PositiveIntegerField(null=True, blank=True)
    second_name = models.CharField(max_length=100, null=True, blank=True)
    middle_name = models.CharField(max_length=100, null=True, blank=True)
    middle_initial = models.CharField(max_length=5, null=True, blank=True)
    suffix = models.CharField(max_length=5, null=True, blank=True) 
    street = models.CharField(max_length=255, null=True, blank=True)
    barangay = models.CharField(max_length=100, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    province = models.CharField(max_length=100, null=True, blank=True)
    zip_code = models.CharField(max_length=10, null=True, blank=True)
    birthday = models.DateField(null=True, blank=True)
    contact_number = models.CharField(max_length=15, null=True, blank=True)
    current_degree = models.CharField(max_length=10, choices=DEGREE_CHOICES, null=True, blank=True)
    is_archived = models.BooleanField(default=False)
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, null=True, blank=True)
    religion = models.CharField(max_length=20, choices=RELIGION_CHOICES, null=True, blank=True)
    practical_catholic = models.BooleanField(default=True)
    marital_status = models.CharField(max_length=20, choices=MARITAL_STATUS_CHOICES, null=True, blank=True)
    occupation = models.CharField(max_length=100, null=True, blank=True)
    recruiter_name = models.CharField(max_length=200, null=True, blank=True)
    voluntary_join = models.BooleanField(default=False)
    e_signature = models.ImageField(upload_to='e_signatures/', null=True, blank=True)
    join_reason = models.TextField(null=True, blank=True)

    def save(self, *args, **kwargs):
        if self.username == 'Mr_Admin' and self.role != 'admin':
            self.role = 'admin'
        if self.birthday:  # Calculate age if birthday is set
            today = timezone.now().date()
            self.age = today.year - self.birthday.year - ((today.month, today.day) < (self.birthday.month, self.birthday.day))
            
        # Generate middle_initial from middle_name if provided
        if self.middle_name and not self.middle_initial:
            self.middle_initial = self.middle_name[0] + "."
            
        super().save(*args, **kwargs)
        if self.profile_picture:
            img = Image.open(self.profile_picture.path)
            output_size = (200, 200)
            img = img.resize(output_size, Image.Resampling.LANCZOS)
            img.save(self.profile_picture.path)
    
    def get_current_degree_display(self):
        """Return the display value for current degree"""
        if self.current_degree:
            return dict(self.DEGREE_CHOICES)[self.current_degree]
        return "Not specified"
    
    def is_inactive_member(self):
        """Check if member is inactive (no activity for 30 days)"""
        from datetime import timedelta
        
        # Only check for members and officers, not admin or pending
        if self.role not in ['member', 'officer']:
            return False
        
        # Grace period: newly accepted members get 30 days before being considered for inactivity
        thirty_days_ago = timezone.now().date() - timedelta(days=30)
        
        # If user was approved/joined within the last 30 days, they're not inactive
        if self.date_joined and self.date_joined.date() > thirty_days_ago:
            return False
            
        # Check for recent recruitment activity
        recent_recruitments = self.recruitments.filter(date_recruited__gte=thirty_days_ago).exists()
        
        # Check for recent event attendance
        recent_attendance = self.event_attendances.filter(
            event__date_from__gte=thirty_days_ago,
            is_present=True
        ).exists()
        
        # Member is inactive if they have no recent recruitment or attendance activity
        return not (recent_recruitments or recent_attendance)
    
    def get_activity_status(self):
        """Get activity status with warning level"""
        if self.is_inactive_member():
            return {
                'status': 'inactive',
                'warning': True,
                'message': 'No activity in the last 30 days',
                'class': 'warning-badge inactive'
            }
        return {
            'status': 'active',
            'warning': False,
            'message': 'Active member',
            'class': 'status-badge active'
        }


class Event(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )
    
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    description = models.TextField()
    category = models.CharField(max_length=100)
    subcategory = models.CharField(max_length=100, null=True, blank=True)
    council = models.ForeignKey('Council', on_delete=models.CASCADE, null=True, blank=True)
    is_global = models.BooleanField(default=False)
    street = models.CharField(max_length=255)
    barangay = models.CharField(max_length=255)
    city = models.CharField(max_length=255)
    province = models.CharField(max_length=255)
    date_from = models.DateField()
    date_until = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_by = models.ForeignKey('User', on_delete=models.SET_NULL, null=True, related_name='created_events')
    approved_by = models.ForeignKey('User', on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_events')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    rejection_reason = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return self.name

    enable_attendance = models.BooleanField(default=True, help_text="Enable attendance tracking for this event")


class EventAttendance(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='attendances')
    member = models.ForeignKey(User, on_delete=models.CASCADE, related_name='event_attendances')
    is_present = models.BooleanField(default=False)
    recorded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='recorded_attendances')
    recorded_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['event', 'member']
        verbose_name = 'Event Attendance'
        verbose_name_plural = 'Event Attendances'
        
    def __str__(self):
        status = "Present" if self.is_present else "Absent"
        return f"{self.member.username} - {self.event.name} - {status}"

class ForumCategory(models.Model):
    CATEGORY_CHOICES = [
        ('general', 'General'),
        ('event_proposals', 'Event Proposals'),
        ('announcements', 'Announcements'),
        ('feedback', 'Feedback & Suggestions'),
        ('questions', 'Questions'),
        ('urgent', 'Urgent'),
    ]
    
    name = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    description = models.TextField(blank=True)
    
    def __str__(self):
        return self.get_name_display()
    
    class Meta:
        verbose_name_plural = "Forum Categories"

class ForumMessage(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    category = models.ForeignKey(ForumCategory, on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_pinned = models.BooleanField(default=False)
    council = models.ForeignKey(Council, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='forum_images/', null=True, blank=True)
    is_district_forum = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.sender.username} - {self.timestamp.strftime('%Y-%m-%d %H:%M')}"
    
    class Meta:
        ordering = ['-is_pinned', '-timestamp']

class Analytics(models.Model):
    council = models.ForeignKey(Council, on_delete=models.CASCADE)
    events_count = models.IntegerField(default=0)
    donations_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    date_updated = models.DateTimeField(auto_now=True)  

    def __str__(self):
        return f"Analytics for {self.council.name} on {self.date_updated}"
    
class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    message = models.ForeignKey(ForumMessage, on_delete=models.CASCADE, null=True, blank=True)
    title = models.CharField(max_length=255, null=True, blank=True)
    content = models.TextField(null=True, blank=True)
    is_read = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        if self.message:
            return f"Forum notification for {self.user.username} - {self.timestamp.strftime('%Y-%m-%d %H:%M')}"
        return f"Notification for {self.user.username}: {self.title} - {self.timestamp.strftime('%Y-%m-%d %H:%M')}"
    
    class Meta:
        ordering = ['-timestamp']

class Block(models.Model):
    index = models.IntegerField()
    timestamp = models.DateTimeField()
    transactions = models.JSONField(default=list)
    proof = models.BigIntegerField()
    previous_hash = models.CharField(max_length=64)
    hash = models.CharField(max_length=64)

    def calculate_hash(self):
        if not isinstance(self.timestamp, datetime):
            logger.error(f"Invalid timestamp for Block {self.index}: {self.timestamp}, type={type(self.timestamp)}")
            self.timestamp = timezone.now()
        block_string = json.dumps(
            {
                'index': self.index,
                'timestamp': self.timestamp.isoformat(),
                'transactions': self.transactions,
                'proof': self.proof,
                'previous_hash': self.previous_hash
            },
            sort_keys=True
        ).encode()
        calculated_hash = hashlib.sha256(block_string).hexdigest()
        logger.debug(f"Calculated hash for Block {self.index}: {calculated_hash}")
        return calculated_hash

    def save(self, *args, **kwargs):
        if self.timestamp is None:
            self.timestamp = timezone.now()
        old_hash = self.hash
        self.hash = self.calculate_hash()
        logger.info(f"Saving Block {self.index}: Old hash={old_hash}, New hash={self.hash}")
        super().save(*args, **kwargs)
        logger.info(f"Block {self.index} saved with hash={self.hash}")

def block_pre_save(sender, instance, **kwargs):
    if instance.pk:
        logger.error(f"Attempt to modify Block {instance.index} rejected")
        raise ValidationError("Block modifications are not allowed")
pre_save.connect(block_pre_save, sender=Block)  

class Blockchain(models.Model):
    pending_transactions = models.JSONField(default=list)

    def initialize_chain(self):
        if not Block.objects.exists():
            logger.info("Initializing blockchain with genesis block")
            genesis_block = Block(
                index=1,
                timestamp=timezone.now(),
                transactions=[],
                proof=1,
                previous_hash='0',
                hash='0'
            )
            genesis_block.save()
            logger.info("Genesis block created")

    def get_chain(self):
        blocks = Block.objects.all().order_by('index')
        chain = []
        for block in blocks:
            chain.append({
                'index': block.index,
                'timestamp': block.timestamp.isoformat() if isinstance(block.timestamp, datetime) else str(block.timestamp),
                'transactions': block.transactions,
                'proof': block.proof,
                'previous_hash': block.previous_hash,
                'hash': block.hash
            })
        return chain

    def add_transaction(self, donation, public_key):
        try:
            if not donation.verify_signature(public_key):
                logger.error(f"Invalid signature for donation {donation.transaction_id}")
                return False

            transaction = {
                'transaction_id': donation.transaction_id,
                'donor': f"{donation.first_name} {donation.last_name}" if donation.first_name != "Anonymous" else "Anonymous",
                'email': donation.email if donation.email else "N/A",
                'amount': str(donation.amount),
                'date': donation.donation_date.strftime('%Y-%m-%d') if donation.donation_date else "N/A",  # Ensure date is in YYYY-MM-DD format
                'payment_method': donation.payment_method,
                'status': donation.status,  # Add status field
                'timestamp': timezone.now().isoformat()
            }
            
            self.pending_transactions.append(transaction)
            self.save()
            logger.info(f"Transaction {donation.transaction_id} added to pending transactions")
            return True
        except Exception as e:
            logger.error(f"Error adding transaction: {str(e)}")
            return False
    
    def get_previous_block(self):
        try:
            latest_block = Block.objects.latest('index')
            return {
                'index': latest_block.index,
                'timestamp': latest_block.timestamp.isoformat() if isinstance(latest_block.timestamp, datetime) else str(latest_block.timestamp),
                'transactions': latest_block.transactions,
                'proof': latest_block.proof,
                'previous_hash': latest_block.previous_hash,
                'hash': latest_block.hash
            }
        except Block.DoesNotExist:
            return None

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash_block(self, block):
        if not isinstance(block['timestamp'], str):
            block['timestamp'] = block['timestamp'].isoformat() if isinstance(block['timestamp'], datetime) else str(block['timestamp'])
            
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self):
        blocks = Block.objects.all().order_by('index')
        if not blocks:
            return True
            
        previous_block = None
        for block in blocks:
            if previous_block:
                if block.previous_hash != previous_block.hash:
                    logger.error(f"Invalid hash link at block {block.index}")
                    return False
                    
                hash_operation = hashlib.sha256(str(block.proof**2 - previous_block.proof**2).encode()).hexdigest()
                if hash_operation[:4] != '0000':
                    logger.error(f"Invalid proof of work at block {block.index}")
                    return False
            previous_block = block
            
        return True

    def create_block(self, proof, previous_hash=None):
        try:
            previous_block = self.get_previous_block()
            if not previous_block:
                index = 1
                previous_hash = '0'
            else:
                index = previous_block['index'] + 1
                previous_hash = previous_hash or previous_block['hash']
                
            timestamp = timezone.now()
            
            block = Block(
                index=index,
                timestamp=timestamp,
                transactions=self.pending_transactions,
                proof=proof,
                previous_hash=previous_hash,
                hash=''  # Will be calculated in save()
            )
            block.save()
            
            self.pending_transactions = []
            self.save()
            
            logger.info(f"Block {index} created successfully")
            return {
                'index': block.index,
                'timestamp': block.timestamp.isoformat(),
                'transactions': block.transactions,
                'proof': block.proof,
                'previous_hash': block.previous_hash,
                'hash': block.hash
            }
        except Exception as e:
            logger.error(f"Error creating block: {str(e)}")
            return None

# Global blockchain instance
blockchain = Blockchain.objects.first()
if blockchain is None:
    try:
        blockchain = Blockchain.objects.create()
    except Exception as e:
        logger.error(f"Error creating blockchain: {str(e)}")
        blockchain = SimpleLazyObject(lambda: Blockchain.objects.first() or Blockchain())

def get_blockchain():
    global blockchain
    if blockchain is None or (hasattr(blockchain, '_wrapped') and blockchain._wrapped is None):
        try:
            blockchain = Blockchain.objects.first() or Blockchain.objects.create()
        except Exception as e:
            logger.error(f"Error getting blockchain: {str(e)}")
            return None
    return blockchain

class Donation(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('pending_manual', 'Pending Manual'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    )
    PAYMENT_METHOD_CHOICES = (
        ('gcash', 'GCash'),
        ('manual', 'Manual'),
    )

    transaction_id = models.CharField(max_length=100, unique=True, default=generate_transaction_id)
    first_name = models.CharField(max_length=100)
    middle_initial = models.CharField(max_length=10, blank=True)
    last_name = models.CharField(max_length=100)
    email = models.EmailField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    donation_date = models.DateField(default=timezone.now)
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES, default='manual')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    source_id = models.CharField(max_length=100, blank=True, null=True)
    signature = models.TextField(blank=True, null=True)
    council = models.ForeignKey('Council', on_delete=models.SET_NULL, null=True, blank=True)
    is_anonymous = models.BooleanField(default=False, help_text="Whether the donor wishes to remain anonymous in public records.")
    submitted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='submitted_donations',
        null=True,
        blank=True
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='reviewed_donations',
        null=True,
        blank=True
    )
    rejection_reason = models.TextField(blank=True, null=True)
    receipt = models.ImageField(upload_to='donation_receipts/', null=True, blank=True)
    event = models.ForeignKey('Event', on_delete=models.SET_NULL, null=True, blank=True, related_name='donations')

    def sign_donation(self, private_key):
        """Sign the donation data with the provided private key"""
        try:
            # Use is_anonymous to determine display name for signing
            first_name = "Anonymous" if self.is_anonymous else (self.first_name or "")
            last_name = "" if self.is_anonymous else (self.last_name or "")
            email = "anonymous@example.com" if self.is_anonymous else (self.email or "")
            event_info = self.event.name if self.event else "General Donation"

            donation_data = f"{self.transaction_id}:{first_name}:{last_name}:{email}:{self.amount}:{self.donation_date.isoformat() if isinstance(self.donation_date, date) else str(self.donation_date)}:{self.payment_method}:{event_info}"
            
            signature = private_key.sign(
                donation_data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            self.signature = base64.b64encode(signature).decode('utf-8')
            return True
        except Exception as e:
            logger.error(f"Error signing donation: {str(e)}")
            return False

    def verify_signature(self, public_key):
        """Verify the donation signature using the provided public key"""
        if not self.signature:
            logger.error(f"No signature found for donation {self.transaction_id}")
            return False
            
        try:
            # Reconstruct data using is_anonymous for verification
            first_name = "Anonymous" if self.is_anonymous else (self.first_name or "")
            last_name = "" if self.is_anonymous else (self.last_name or "")
            email = "anonymous@example.com" if self.is_anonymous else (self.email or "")
            event_info = self.event.name if self.event else "General Donation"

            donation_data = f"{self.transaction_id}:{first_name}:{last_name}:{email}:{self.amount}:{self.donation_date.isoformat() if isinstance(self.donation_date, date) else str(self.donation_date)}:{self.payment_method}:{event_info}"
            signature = base64.b64decode(self.signature)
            
            public_key.verify(
                signature,
                donation_data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            logger.error(f"Invalid signature for donation {self.transaction_id}")
            return False
        except Exception as e:
            logger.error(f"Error verifying signature: {str(e)}")
            return False

    def get_display_name(self):
        """Helper method to get donor name for displays (e.g., ledgers)"""
        if self.is_anonymous:
            return "Anonymous Donor"
        return f"{self.first_name or ''} {self.middle_initial or ''} {self.last_name or ''}".strip()

    def __str__(self):
        display_name = self.get_display_name()
        return f"{display_name} - {self.amount} - {self.get_status_display()}"    

def receipt_upload_path(instance, filename):
    ext = filename.split('.')[-1]
    new_filename = f"{instance.transaction_id}.{ext}"
    return os.path.join('donation_receipts', new_filename)

class Recruitment(models.Model):
    """Model to track recruitments and relationships between recruiters and recruits"""
    recruiter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='recruitments')
    recruited = models.ForeignKey(User, on_delete=models.CASCADE, related_name='recruited_by')
    date_recruited = models.DateField(default=timezone.now)
    is_manual = models.BooleanField(default=False)  # True if manually added by admin
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='added_recruitments')
    
    class Meta:
        unique_together = ('recruiter', 'recruited')
        
    def __str__(self):
        return f"{self.recruiter.username} recruited {self.recruited.username} on {self.date_recruited}"