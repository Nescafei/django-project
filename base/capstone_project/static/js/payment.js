console.log('donations.js loaded successfully');

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB in bytes

function getCsrfToken() {
    const token = document.querySelector('input[name="csrfmiddlewaretoken"]')?.value;
    if (!token) {
        console.error('CSRF token not found');
        alert('CSRF token missing. Please refresh the page.');
    }
    return token;
}

function validateName(input) {
    const warning = document.getElementById(input.id.replace('id_', '') + '_warning');
    let regex;
    
    if (input.id === 'id_first_name') {
        regex = /^[A-Z][a-zA-Z]*$/;
        if (!input.value) {
            warning.textContent = 'First name is required.';
            return false;
        } else if (!regex.test(input.value)) {
            warning.textContent = 'First name must start with a capital letter and contain only letters.';
            return false;
        }
    } else {
        regex = /^[A-Z][a-zA-Z]*( [A-Z][a-zA-Z]*)*$/;
        if (!input.value) {
            warning.textContent = 'Last name is required.';
            return false;
        } else if (!regex.test(input.value)) {
            warning.textContent = 'Last name must start with a capital letter and can include spaces for compound names (e.g., De Torres).';
            return false;
        }
    }
    
    warning.textContent = '';
    return true;
}

function validateMiddleInitial(input) {
    const warning = document.getElementById('middle_initial_warning');
    const regex = /^[A-Z]$/;
    
    if (input.value && !regex.test(input.value)) {
        warning.textContent = 'Middle initial must be a single capital letter.';
        return false;
    }
    
    warning.textContent = '';
    return true;
}

function validateEmail(input) {
    const warning = document.getElementById('email_warning');
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    if (!input.value) {
        warning.textContent = 'Email is required.';
        return false;
    } else if (!regex.test(input.value)) {
        warning.textContent = 'Please enter a valid email address (e.g., user@domain.com).';
        return false;
    }
    
    warning.textContent = '';
    return true;
}

function validateAmount(input) {
    const warning = document.getElementById('amount_warning');
    const amount = parseFloat(input.value);
    
    if (!input.value) {
        warning.textContent = 'Amount is required.';
        return false;
    } else if (isNaN(amount) || amount <= 0) {
        warning.textContent = 'Please enter a valid positive amount.';
        return false;
    } else if (amount > 10000) {
        warning.textContent = 'Amount cannot exceed ₱10,000.';
        return false;
    } else if (amount < 100) {
        warning.textContent = 'Amount must be at least ₱100.';
        return false;
    }
    
    warning.textContent = '';
    return true;
}

function validateForm() {
    const firstNameValid = validateName(document.getElementById('id_first_name'));
    const middleInitialValid = validateMiddleInitial(document.getElementById('id_middle_initial'));
    const lastNameValid = validateName(document.getElementById('id_last_name'));
    const emailValid = validateEmail(document.getElementById('id_email'));
    const amountValid = validateAmount(document.getElementById('id_amount'));
    
    return firstNameValid && middleInitialValid && lastNameValid && emailValid && amountValid;
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM fully loaded');
    const donationForm = document.querySelector('#donationForm');
    if (donationForm) {
        console.log('Donation form found:', donationForm);
        donationForm.addEventListener('submit', function handler(event) {
            console.log('Submit intercepted');
            if (!validateForm()) {
                event.preventDefault();
                console.warn('Validation failed — blocking submit');
                return;
            }
            console.log('Validation passed — submitting...');
            donationForm.removeEventListener('submit', handler);
            event.target.submit();
        });
    } else {
        console.error('Error: Donation form not found');
    }

    const viewBlockchainButton = document.getElementById('view-blockchain');
    if (viewBlockchainButton) {
        console.log('Blockchain button found:', viewBlockchainButton);
        viewBlockchainButton.addEventListener('click', () => {
            console.log('Redirecting to /blockchain/');
            window.location.href = '/blockchain/';
        });
    } else {
        console.error('Error: #view-blockchain not found');
    }
});