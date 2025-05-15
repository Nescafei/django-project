// Log to confirm script is loaded
console.log('payment.js loaded successfully');

// Function to get CSRF token from the form
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
    const donationForm = document.getElementById('donation-form');
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
            const donorEmail = formData.get('donor_email');
            const amount = formData.get('amount');
            const paymentMethod = formData.get('payment_method');

            if (!donorEmail || donorEmail.trim() === '') {
                console.error('Validation failed: No donor email');
                alert('Please enter a donor email');
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
            if (!paymentMethod) {
                console.error('Validation failed: No payment method');
                alert('Please select a payment method');
                return;
            }

            try {
                let response, responseData;
                const csrfToken = getCsrfToken();
                if (!csrfToken) return;

                if (paymentMethod === 'paypal') {
                    console.log('Sending PayPal request:', formEntries);
                    response = await fetch('/initiate_paypal_payment/', {
                        method: 'POST',
                        headers: {
                            'X-CSRFToken': csrfToken,
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: new URLSearchParams(formData),
                    });

                    console.log('Response status:', response.status, 'OK:', response.ok);
                    if (!response.ok) {
                        const text = await response.text();
                        console.error('Response text:', text.slice(0, 200));
                        throw new Error(`HTTP error ${response.status}: ${text.slice(0, 100)}`);
                    }

                    responseData = await response.json();
                    console.log('PayPal response:', responseData);
                    if (responseData.error) {
                        console.error('PayPal error:', responseData.error);
                        alert('PayPal Error: ' + responseData.error);
                        return;
                    }

                    console.log('PayPal form HTML:', responseData.form);
                    const formContainer = document.createElement('div');
                    formContainer.innerHTML = responseData.form;
                    document.body.appendChild(formContainer);
                    let paypalForm = formContainer.querySelector('form');
                    if (!paypalForm) {
                        console.warn('PayPal form not found, creating one');
                        paypalForm = document.createElement('form');
                        paypalForm.action = 'https://www.sandbox.paypal.com/cgi-bin/webscr';
                        paypalForm.method = 'post';
                        paypalForm.innerHTML = responseData.form;
                        formContainer.appendChild(paypalForm);
                    }
                    console.log('PayPal form found or created:', paypalForm);
                    paypalForm.submit();
                } else if (paymentMethod === 'gcash') {
                    console.log('Sending GCash request:', formEntries);
                    response = await fetch('/initiate_gcash_payment/', {
                        method: 'POST',
                        headers: {
                            'X-CSRFToken': csrfToken,
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: new URLSearchParams(formData),
                    });

                    console.log('Response status:', response.status, 'OK:', response.ok);
                    if (!response.ok) {
                        const text = await response.text();
                        console.error('Response text:', text.slice(0, 200));
                        throw new Error(`HTTP error ${response.status}: ${text.slice(0, 100)}`);
                    }

                    responseData = await response.json();
                    console.log('GCash response:', responseData);
                    if (responseData.error) {
                        console.error('GCash error:', responseData.error);
                        alert('GCash Error: ' + responseData.error);
                        return;
                    }
                    if (!responseData.redirect_url) {
                        console.error('No redirect URL received:', responseData);
                        alert('No redirect URL received from server. Please check server logs.');
                        return;
                    }
                    console.log('GCash redirecting to:', responseData.redirect_url);
                    console.log('Current URL before redirect:', window.location.href);
                    alert('Please complete the payment on the next page by entering the OTP (123456 in test mode).');
                    setTimeout(() => {
                        window.location.href = responseData.redirect_url;
                        console.log('Redirect initiated to:', responseData.redirect_url);
                        setTimeout(() => console.log('URL after redirect (if script persists):', window.location.href), 5000);
                    }, 2000);
                }
            } catch (error) {
                console.error('Payment fetch error:', error);
                alert('Payment Error: ' + error.message);
            }
        });
    } else {
        console.error('Error: #donation-form not found');
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