from django.contrib.auth.models import AbstractUser
from django.db import models
from PIL import Image
import os

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
        return f"Analytics for {self.council.name} on {self.date_updated}"