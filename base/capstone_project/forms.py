from django import forms
from .models import Donation
from datetime import date
import uuid

class DonationForm(forms.ModelForm):
    class Meta:
        model = Donation
        fields = ['first_name', 'middle_initial', 'last_name', 'email', 'amount', 'donation_date']
        widgets = {
            'donation_date': forms.DateInput(attrs={'type': 'date'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.initial['donation_date'] = date.today()

    def clean_amount(self):
        amount = self.cleaned_data.get('amount')
        if amount is None or amount <= 0:
            raise forms.ValidationError("Amount must be greater than 0.")
        if amount < 100:
            raise forms.ValidationError("Amount must be at least ₱100.")
        return amount

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not email:
            raise forms.ValidationError("Email is required.")
        return email

class ManualDonationForm(forms.ModelForm):
    class Meta:
        model = Donation
        fields = ['first_name', 'middle_initial', 'last_name', 'email', 'amount', 'donation_date', 'signature']
        widgets = {
            'donation_date': forms.DateInput(attrs={'type': 'date'}),
            'signature': forms.Textarea(attrs={'rows': 4, 'cols': 50}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.pk:
            self.initial['transaction_id'] = f"MANUAL-{uuid.uuid4().hex[:8]}"
            self.initial['payment_method'] = 'manual'
            self.initial['source_id'] = ''