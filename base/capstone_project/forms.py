from django import forms
from .models import Donation, Event
from datetime import date
import uuid

class DonationForm(forms.ModelForm):
    donate_anonymously = forms.BooleanField(
        required=False,
        label="Donate Anonymously",
        help_text="Check this box to donate without providing personal information."
    )

    class Meta:
        model = Donation
        fields = ['first_name', 'middle_initial', 'last_name', 'email', 'amount', 'event', 'donate_anonymously']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['event'].queryset = Event.objects.filter(status='approved')  # Only approved events
        self.fields['event'].empty_label = "General Donation"  # Optional choice for None
        self.fields['event'].required = False  # Not required
        for field in ['first_name', 'middle_initial', 'last_name', 'email']:
            self.fields[field].required = False  # Make optional to support anonymity

    def clean(self):
        cleaned_data = super().clean()
        donate_anonymously = cleaned_data.get('donate_anonymously', False)
        amount = cleaned_data.get('amount')

        if not donate_anonymously:
            if not cleaned_data.get('first_name'):
                self.add_error('first_name', "First name is required unless donating anonymously.")
            if not cleaned_data.get('last_name'):
                self.add_error('last_name', "Last name is required unless donating anonymously.")
            if not cleaned_data.get('email'):
                self.add_error('email', "Email is required unless donating anonymously.")

        if amount is None or amount <= 0:
            self.add_error('amount', "Amount must be greater than 0.")
        if amount and amount < 100:
            self.add_error('amount', "Amount must be at least ₱100.")

        return cleaned_data

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
    donate_anonymously = forms.BooleanField(
        required=False,
        label="Donate Anonymously",
        help_text="Check this box to donate without providing personal information."
    )

    class Meta:
        model = Donation
        fields = ['first_name', 'middle_initial', 'last_name', 'email', 'amount', 'event', 'donation_date', 'receipt', 'donate_anonymously']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.pk:
            self.initial['transaction_id'] = f"KC-{uuid.uuid4().hex[:8]}"
            self.initial['payment_method'] = 'manual'
            self.initial['source_id'] = ''
            self.initial['donation_date'] = date.today()  # Default to today, but editable
        for field in ['first_name', 'middle_initial', 'last_name', 'email']:
            self.fields[field].required = False
        self.fields['event'].queryset = Event.objects.filter(status='approved')  # Only approved events
        self.fields['event'].empty_label = "General Donation"  # Optional choice for None
        self.fields['event'].required = False  # Not required
        self.fields['donation_date'].required = True  # Ensure date is required
        self.fields['receipt'].required = False  # Optional receipt upload

    def clean(self):
        cleaned_data = super().clean()
        donate_anonymously = cleaned_data.get('donate_anonymously', False)
        amount = cleaned_data.get('amount')
        donation_date = cleaned_data.get('donation_date')

        if not donate_anonymously:
            if not cleaned_data.get('first_name'):
                self.add_error('first_name', "First name is required unless donating anonymously.")
            if not cleaned_data.get('last_name'):
                self.add_error('last_name', "Last name is required unless donating anonymously.")
            if not cleaned_data.get('email'):
                self.add_error('email', "Email is required unless donating anonymously.")

        if amount is None or amount <= 0:
            self.add_error('amount', "Amount must be greater than 0.")
        if amount and amount < 100:
            self.add_error('amount', "Amount must be at least ₱100.")
        if not donation_date:
            self.add_error('donation_date', "Donation date is required.")

        return cleaned_data
