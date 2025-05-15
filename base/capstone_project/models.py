import hashlib
import json
from django.utils import timezone
import datetime
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from PIL import Image
import os
import logging

logger = logging.getLogger(__name__)

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
    index = models.IntegerField(default=1)
    timestamp = models.FloatField()  # Remove default=timezone.now().timestamp()
    transactions = models.JSONField(default=list)
    proof = models.BigIntegerField()
    previous_hash = models.CharField(max_length=64)
    hash = models.CharField(max_length=64, blank=True)

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.transactions}{self.proof}{self.previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def __str__(self):
        return f"Block {self.index}"

class Blockchain:
    def __init__(self):
        self._genesis_initialized = False

    def initialize_genesis_block(self):
        if not self._genesis_initialized and not Block.objects.exists():
            self.create_block(proof=1, previous_hash='0')
            logger.info("Genesis block created")
        self._genesis_initialized = True

    def create_block(self, proof, previous_hash):
        block = Block(
            proof=proof,
            previous_hash=previous_hash,
            timestamp=timezone.now().timestamp()  # Set timestamp here
        )
        if Block.objects.exists():
            block.index = Block.objects.latest('index').index + 1
        else:
            block.index = 1
        block.save()
        block.hash = block.calculate_hash()
        block.save()
        return block

    def add_transaction(self, amount, payment_method, transaction_id):
        self.initialize_genesis_block()
        transaction = f"Amount: ₱{amount}, Method: {payment_method}, Transaction ID: {transaction_id}"
        latest_block = Block.objects.latest('index')
        if len(latest_block.transactions) < 10:
            latest_block.transactions.append(transaction)
            latest_block.hash = latest_block.calculate_hash()
            latest_block.save()
            return latest_block.index
        else:
            proof = self.proof_of_work(latest_block.proof)
            previous_hash = latest_block.hash
            new_block = self.create_block(proof, previous_hash)
            new_block.transactions.append(transaction)
            new_block.hash = new_block.calculate_hash()
            new_block.save()
            return new_block.index

    def add_block(self, donation):
        if donation.status != 'completed':
            logger.warning(f"Cannot add block for Donation {donation.id}: Status is {donation.status}")
            return None
        logger.info(f"Adding block for Donation {donation.id}: Amount {donation.amount}, Method {donation.payment_method}")
        return self.add_transaction(float(donation.amount), donation.payment_method, donation.transaction_id)

    def proof_of_work(self, last_proof):
        proof = 0
        while not self.is_valid_proof(last_proof, proof):
            proof += 1
        return proof

    def is_valid_proof(self, last_proof, proof):
        guess = f"{last_proof}{proof}".encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def get_chain(self):
        self.initialize_genesis_block()
        chain = [
            {
                'index': b.index,
                'timestamp': datetime.datetime.fromtimestamp(b.timestamp, tz=timezone.get_current_timezone()),
                'transactions': b.transactions,
                'proof': b.proof,
                'previous_hash': b.previous_hash,
                'hash': b.hash
            } for b in Block.objects.all()
        ]
        logger.info(f"Retrieved blockchain with {len(chain)} blocks")
        return chain

    def is_chain_valid(self):
        blocks = Block.objects.all()
        for i in range(1, len(blocks)):
            current_block = blocks[i]
            previous_block = blocks[i - 1]
            if current_block.previous_hash != previous_block.hash:
                return False
            if not self.is_valid_proof(previous_block.proof, current_block.proof):
                return False
        return True

blockchain = Blockchain()

class Donation(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('pending_manual', 'Pending Manual Review'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    donor_name = models.CharField(max_length=100)
    donor_email = models.EmailField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=50, choices=[
        ('paypal', 'PayPal'),
        ('gcash', 'GCash'),
        ('manual', 'Manual'),
        ('online', 'Online'),
    ])
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    transaction_id = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    donation_date = models.DateField(null=True, blank=True)
    receipt = models.FileField(upload_to='receipts/', null=True, blank=True)
    notes = models.TextField(blank=True)
    submitted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='submitted_donations')
    block_index = models.IntegerField(null=True, blank=True)
    source_id = models.CharField(max_length=100, null=True, blank=True)

    def clean(self):
        if self.amount <= 0:
            raise ValidationError("Amount must be greater than 0")

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Donation {self.id} - {self.donor_email} ({self.amount} {self.payment_method})"