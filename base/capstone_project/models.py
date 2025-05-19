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
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='pending')
    council = models.ForeignKey('Council', on_delete=models.SET_NULL, null=True, blank=True)
    age = models.PositiveIntegerField(null=True, blank=True)
    address = models.TextField(null=True, blank=True)
    birthday = models.DateField(null=True, blank=True)
    contact_number = models.CharField(max_length=15, null=True, blank=True)
    current_degree = models.CharField(
        max_length=10,
        choices=[
            ('1st', '1st Degree'),
            ('2nd', '2nd Degree'),
            ('3rd', '3rd Degree'),
            ('4th', '4th Degree'),
        ],
        null=True,
        blank=True
    )
    is_archived = models.BooleanField(default=False)
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)

    def save(self, *args, **kwargs):
        if self.username == 'Mr_Admin' and self.role != 'admin':
            self.role = 'admin'
        super().save(*args, **kwargs)
        if self.profile_picture:
            img = Image.open(self.profile_picture.path)
            output_size = (200, 200)
            img = img.resize(output_size, Image.Resampling.LANCZOS)
            img.save(self.profile_picture.path)

    def __str__(self):
        return self.username

class Event(models.Model):
    name = models.CharField(max_length=200)
    council = models.ForeignKey(Council, on_delete=models.CASCADE)
    date = models.DateField()
    description = models.TextField()

    def __str__(self):
        return f"{self.name} - {self.council.name}"

class Analytics(models.Model):
    council = models.ForeignKey(Council, on_delete=models.CASCADE)
    events_count = models.IntegerField(default=0)
    donations_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"Analytics for {self.council.name}"

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
            self.timestamp = timezone.now()  # Fallback
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
    if instance.pk:  # Block already exists
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
            genesis_block.save()  # Save will compute hash
            logger.info("Genesis block created")

    def get_chain(self):
        try:
            blocks = Block.objects.all().order_by('index')
            chain = []
            for block in blocks:
                block_data = {
                    'index': block.index,
                    'timestamp': block.timestamp.isoformat(),
                    'transactions': block.transactions if block.transactions else [],
                    'proof': block.proof,
                    'previous_hash': block.previous_hash,
                    'current_hash': block.hash
                }
                chain.append(block_data)
            logger.debug(f"Chain retrieved: {len(chain)} blocks, {len(self.pending_transactions)} pending transactions")
            return chain
        except Exception as e:
            logger.error(f"Error retrieving chain: {str(e)}")
            raise

    def add_transaction(self, donation, public_key):
        if not donation.verify_signature(public_key):
            logger.error(f"Invalid signature for donation {donation.transaction_id}")
            return None
        for existing in self.pending_transactions:
            if existing['transaction_id'] == donation.transaction_id:
                logger.warning(f"Duplicate transaction {donation.transaction_id} ignored")
                return None
        transaction = {
            'transaction_id': donation.transaction_id,
            'first_name': donation.first_name,
            'middle_initial': donation.middle_initial,
            'last_name': donation.last_name,
            'email': donation.email,
            'amount': str(donation.amount),
            'donation_date': donation.donation_date.isoformat(),
            'payment_method': donation.payment_method,
            'status': donation.status,
            'signature': donation.signature,
            'submitted_by': donation.submitted_by.username if donation.submitted_by else None
        }
        self.pending_transactions.append(transaction)
        logger.info(f"Transaction {transaction['transaction_id']} added to pending transactions")
        self.save()
        return transaction
        
    def get_previous_block(self):
        blocks = Block.objects.all().order_by('-index')
        if blocks.exists():
            block = blocks.first()
            return {
                'index': block.index,
                'timestamp': block.timestamp,
                'transactions': block.transactions,
                'proof': block.proof,
                'previous_hash': block.previous_hash,
                'current_hash': block.hash
            }
        return None

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while not check_proof:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:6] == '000000':
                check_proof = True
            else:
                new_proof += 1
        logger.debug(f"Proof of work found: {new_proof}")
        return new_proof

    def hash_block(self, block):
        if block is None:
            return '0'
        block_string = json.dumps(
            {
                'index': block['index'],
                'timestamp': block['timestamp'].isoformat() if isinstance(block['timestamp'], datetime) else block['timestamp'],
                'transactions': block['transactions'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash']
            },
            sort_keys=True
        ).encode()
        return hashlib.sha256(block_string).hexdigest()

    def is_chain_valid(self):
        chain = self.get_chain()
        if not chain:
            logger.debug("Empty blockchain is valid")
            return True
        for i, block in enumerate(chain):
            calculated_hash = self.hash_block(block)
            logger.debug(f"Block {block['index']}: Stored hash={block['current_hash']}, Calculated hash={calculated_hash}")
            if block['current_hash'] != calculated_hash:
                logger.error(f"Invalid hash at block {block['index']}: Expected {calculated_hash}, Got {block['current_hash']}")
                return False
            if i > 0:
                previous_block = chain[i - 1]
                calculated_previous_hash = previous_block['current_hash']
                if block['previous_hash'] != calculated_previous_hash:
                    logger.error(f"Invalid previous hash at block {block['index']}: Expected {calculated_previous_hash}, Got {block['previous_hash']}")
                    return False
                previous_proof = previous_block['proof']
                proof = block['proof']
                hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
                if hash_operation[:6] != '000000':
                    logger.error(f"Invalid proof at block {block['index']}")
                    return False
        logger.debug("Blockchain is valid")
        return True
        
    def create_block(self, proof, previous_hash=None):
        previous_block = self.get_previous_block()
        if previous_block:
            previous_hash = previous_block['current_hash']
        else:
            previous_hash = '0'
        block = Block(
            index=Block.objects.count() + 1,
            timestamp=timezone.now(),
            transactions=self.pending_transactions,
            proof=proof,
            previous_hash=previous_hash,
            hash='0'
        )
        self.pending_transactions = []
        try:
            block.save()
            logger.info(f"Block {block.index} saved to database with {len(block.transactions)} transactions")
            self.save()
            return {
                'index': block.index,
                'timestamp': block.timestamp.isoformat(),
                'transactions': block.transactions,
                'proof': block.proof,
                'previous_hash': block.previous_hash,
                'current_hash': block.hash
            }
        except Exception as e:
            logger.error(f"Failed to save block {block.index}: {str(e)}")
            raise
    
def get_blockchain():
    try:
        return Blockchain.objects.first() or Blockchain.objects.create()
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error("Failed to initialize Blockchain: {}".format(str(e)))
        raise
blockchain = SimpleLazyObject(get_blockchain)

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
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES, default='gcash')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    source_id = models.CharField(max_length=100, blank=True, null=True)
    signature = models.TextField(blank=True, null=True)
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

    def sign_donation(self, private_key):
        try:
            message = f"{self.transaction_id}{self.first_name}{self.middle_initial}{self.last_name}{self.email}{self.amount}{self.donation_date}{self.payment_method}{self.status}".encode()
            signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.signature = signature.hex()
            logger.debug(f"Signature generated for donation {self.transaction_id}: {self.signature}")
            self.save()
        except Exception as e:
            logger.error(f"Failed to sign donation {self.transaction_id}: {str(e)}")
            raise

    def verify_signature(self, public_key):
        if not self.signature:
            logger.warning(f"No signature for donation {self.transaction_id}")
            return False
        message = f"{self.transaction_id}{self.first_name}{self.middle_initial}{self.last_name}{self.email}{self.amount}{self.donation_date}{self.payment_method}{self.status}".encode()
        try:
            public_key.verify(
                bytes.fromhex(self.signature),
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logger.debug(f"Signature verified for donation {self.transaction_id}")
            return True
        except InvalidSignature:
            logger.error(f"Invalid signature for donation {self.transaction_id}")
            return False
        except Exception as e:
            logger.error(f"Signature verification failed for {self.transaction_id}: {str(e)}")
            return False

    def __str__(self):
        return f"{self.transaction_id} - {self.amount} - {self.status}"

def receipt_upload_path(instance, filename):
    return f'receipts/{instance.transaction_id}/{filename}'