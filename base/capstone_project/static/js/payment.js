console.log('payment.js loaded successfully');

function getCsrfToken() {
    const token = document.querySelector('input[name="csrfmiddlewaretoken"]')?.value;
    if (!token) {
        console.error('CSRF token not found');
        alert('CSRF token missing. Please refresh the page.');
    }
    return token;
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM fully loaded');
    const donationForm = document.querySelector('form');
    if (donationForm) {
        console.log('Donation form found:', donationForm);
        donationForm.addEventListener('submit', async (event) => {
            console.log('Form submit event triggered');
            event.preventDefault();
            event.stopPropagation();

            const formData = new FormData(event.target);
            const formEntries = {};
            for (const [key, value] of formData.entries()) {
                formEntries[key] = value;
            }
            console.log('Raw form data:', formEntries);

            // Validate inputs
            const firstName = formData.get('first_name');
            const lastName = formData.get('last_name');
            const email = formData.get('email');
            const amount = formData.get('amount');

            if (!firstName || firstName.trim() === '') {
                console.error('Validation failed: No first name');
                alert('Please enter your first name');
                return;
            }
            if (!lastName || lastName.trim() === '') {
                console.error('Validation failed: No last name');
                alert('Please enter your last name');
                return;
            }
            if (!email || email.trim() === '') {
                console.error('Validation failed: No email');
                alert('Please enter an email');
                return;
            }
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                console.error('Validation failed: Invalid email format');
                alert('Please enter a valid email address');
                return;
            }
            if (!amount || amount.trim() === '' || isNaN(amount) || parseFloat(amount) <= 0) {
                console.error('Validation failed: Invalid or missing amount');
                alert('Please enter a valid amount greater than 0');
                return;
            }
            if (parseFloat(amount) > 10000) {
                console.error('Validation failed: Amount exceeds ₱10,000');
                alert('Amount cannot exceed ₱10,000');
                return;
            }
            if (parseFloat(amount) < 100) {
                console.error('Validation failed: Amount below ₱100');
                alert('Amount must be at least ₱100');
                return;
            }

            // Submit form
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