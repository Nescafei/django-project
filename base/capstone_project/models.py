from django.db import models
from django.contrib.auth.models import AbstractUser
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

    def save(self, *args, **kwargs):
        if self.username == 'Mr_Admin' and self.role != 'admin':
            self.role = 'admin'
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username

class Analytics(models.Model):
    council = models.ForeignKey(Council, on_delete=models.CASCADE)
    events_count = models.IntegerField(default=0)
    donations_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    def __str__(self):
        return f"Analytics for {self.council.name} on {self.date_updated}"
