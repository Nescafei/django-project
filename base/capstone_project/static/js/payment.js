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

function validateDate(input) {
    const warning = document.getElementById('donation_date_warning');
    
    if (!input.value) {
        warning.textContent = 'Donation date is required.';
        return false;
    }
    
    const selectedDate = new Date(input.value);
    const today = new Date();
    
    selectedDate.setHours(0, 0, 0, 0);
    today.setHours(0, 0, 0, 0);
    
    if (selectedDate > today) {
        warning.textContent = 'Donation date cannot be in the future.';
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
    const dateValid = validateDate(document.getElementById('id_donation_date'));
    
    return firstNameValid && middleInitialValid && lastNameValid && emailValid && amountValid && dateValid;
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM fully loaded');
    const donationForm = document.querySelector('#donationForm');
    if (donationForm) {
        console.log('Donation form found:', donationForm);
        donationForm.addEventListener('submit', async (event) => {
            console.log('Form submit event triggered');
            event.preventDefault();
            event.stopPropagation();

            if (!validateForm()) {
                console.error('Form validation failed');
                return;
            }

            const formData = new FormData(event.target);
            const formEntries = {};
            for (const [key, value] of formData.entries()) {
                formEntries[key] = value;
            }
            console.log('Raw form data:', formEntries);

            donationForm.submit();
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