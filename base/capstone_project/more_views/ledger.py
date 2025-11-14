from capstone_project.models import blockchain
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.views.decorators.cache import never_cache
from django.core.paginator import Paginator
from django.contrib import messages
from datetime import datetime, date, timezone, timedelta
from django.contrib.auth.decorators import login_required
import logging, csv
from dateutil import parser as date_parser

logger = logging.getLogger(__name__)

@never_cache
@login_required
def get_blockchain_data(request):
    logger.debug("Fetching blockchain data")
    try:
        # Fetch the full blockchain
        full_chain = blockchain.get_chain()  # Assuming this returns a list of blocks
        if not blockchain.is_chain_valid():
            logger.error("Blockchain validation failed")
            messages.error(request, "Blockchain data is corrupted. Contact support.")
            return redirect('donations')
        
        pending_transactions = blockchain.pending_transactions

        # Ensure transaction data is properly structured
        for block in full_chain:
            if not isinstance(block, dict):
                block = {
                    'index': block.index,
                    'timestamp': block.timestamp,
                    'proof': block.proof,
                    'hash': block.hash,
                    'previous_hash': block.previous_hash,
                    'transactions': block.transactions if hasattr(block, 'transactions') else []
                }
            # Parse block timestamp if it's a string
            if isinstance(block.get('timestamp'), str):
                try:
                    block['timestamp'] = date_parser.parse(block['timestamp'])
                except ValueError:
                    block['timestamp'] = None
            for tx in block.get('transactions', []):
                if not isinstance(tx, dict):
                    tx = {
                        'transaction_id': getattr(tx, 'transaction_id', ''),
                        'donor': getattr(tx, 'donor', 'Anonymous'),
                        'email': getattr(tx, 'email', 'N/A'),
                        'amount': getattr(tx, 'amount', '0.00'),  # Starts as string
                        'donation_date': getattr(tx, 'donation_date', None),
                        'payment_method': getattr(tx, 'payment_method', 'N/A'),
                        'status': getattr(tx, 'status', 'Unknown')
                    }
                # Align 'date' key to 'donation_date' if present (from blockchain storage)
                if 'date' in tx and 'donation_date' not in tx:
                    tx['donation_date'] = tx['date']
                # Ensure donation_date is a date object
                if tx.get('donation_date') and isinstance(tx['donation_date'], str):
                    try:
                        tx['donation_date'] = datetime.strptime(tx['donation_date'], '%Y-%m-%d').date()
                    except ValueError:
                        tx['donation_date'] = None
                # Parse transaction timestamp if present and it's a string
                if 'timestamp' in tx and isinstance(tx['timestamp'], str):
                    try:
                        tx['timestamp'] = date_parser.parse(tx['timestamp'])
                    except ValueError:
                        tx['timestamp'] = None
                # Ensure amount is a float
                if 'amount' in tx:
                    if isinstance(tx['amount'], str):
                        try:
                            tx['amount'] = float(tx['amount'].replace('₱', '').replace(',', ''))
                        except ValueError:
                            tx['amount'] = 0.0  # Default to 0.0 if conversion fails
                    elif tx['amount'] is None:
                        tx['amount'] = 0.0  # Handle None case

        for tx in pending_transactions:
            if not isinstance(tx, dict):
                tx = {
                    'transaction_id': getattr(tx, 'transaction_id', ''),
                    'donor': getattr(tx, 'donor', 'Anonymous'),
                    'email': getattr(tx, 'email', 'N/A'),
                    'amount': getattr(tx, 'amount', '0.00'),
                    'donation_date': getattr(tx, 'donation_date', None),
                    'payment_method': getattr(tx, 'payment_method', 'N/A'),
                    'status': getattr(tx, 'status', 'Unknown')
                }
            # Align 'date' key to 'donation_date' if present (from blockchain storage)
            if 'date' in tx and 'donation_date' not in tx:
                tx['donation_date'] = tx['date']
            if tx.get('donation_date') and isinstance(tx['donation_date'], str):
                try:
                    tx['donation_date'] = datetime.strptime(tx['donation_date'], '%Y-%m-%d').date()
                except ValueError:
                    tx['donation_date'] = None
            # Parse transaction timestamp if present and it's a string
            if 'timestamp' in tx and isinstance(tx['timestamp'], str):
                try:
                    tx['timestamp'] = date_parser.parse(tx['timestamp'])
                except ValueError:
                    tx['timestamp'] = None
            if 'amount' in tx and isinstance(tx['amount'], str):
                tx['amount'] = float(tx['amount'].replace('₱', '').replace(',', ''))

        # Apply filters
        search = request.GET.get('search', '').lower()
        date_from = request.GET.get('date_from')
        date_to = request.GET.get('date_to')
        amount_min = request.GET.get('amount_min')
        amount_max = request.GET.get('amount_max')
        status = request.GET.get('status')
        method = request.GET.get('method')

        def matches_filter(tx):
            match = True
            if search and not (tx.get('donor', '').lower().find(search) != -1 or tx.get('transaction_id', '').lower().find(search) != -1):
                match = False
            if date_from and tx.get('donation_date') and tx['donation_date'] < datetime.strptime(date_from, '%Y-%m-%d').date():
                match = False
            if date_to and tx.get('donation_date') and tx['donation_date'] > datetime.strptime(date_to, '%Y-%m-%d').date():
                match = False
            if amount_min and float(amount_min) > tx.get('amount', 0):
                match = False
            if amount_max and float(amount_max) < tx.get('amount', 0):
                match = False
            if status and status != tx.get('status'):
                match = False
            if method and method != tx.get('payment_method'):
                match = False
            return match

        # Filter chain transactions
        filtered_chain = []
        for block in full_chain:
            filtered_txs = [tx for tx in block.get('transactions', []) if matches_filter(tx)]
            if filtered_txs:
                block_copy = block.copy()
                block_copy['transactions'] = filtered_txs
                filtered_chain.append(block_copy)

        # Filter pending transactions
        filtered_pending = [tx for tx in pending_transactions if matches_filter(tx)]

        # Check if CSV export is requested
        if 'csv' in request.GET:
            # Generate filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="donation_ledger_{timestamp}.csv"'

            writer = csv.writer(response)
            writer.writerow(['Block Index', 'Timestamp', 'Proof', 'Current Hash', 'Previous Hash', 'Transaction ID', 'Donor', 'Email', 'Amount', 'Date', 'Method', 'Status'])

            for block in filtered_chain:
                for tx in block['transactions']:
                    writer.writerow([
                        block['index'],
                        block['timestamp'],
                        block['proof'],
                        block['hash'],
                        block['previous_hash'],
                        tx['transaction_id'],
                        tx['donor'],
                        tx.get('email', 'N/A'),
                        tx['amount'],
                        tx.get('donation_date', 'N/A'),
                        tx['payment_method'],
                        tx.get('status', 'Unknown')  # Use get() with default value
                    ])

            writer.writerow([])
            writer.writerow(['Pending Transactions'])
            writer.writerow(['Transaction ID', 'Donor', 'Email', 'Amount', 'Date', 'Method', 'Status'])
            for tx in filtered_pending:
                writer.writerow([
                    tx['transaction_id'],
                    tx['donor'],
                    tx.get('email', 'N/A'),
                    tx['amount'],
                    tx.get('donation_date', 'N/A'),
                    tx['payment_method'],
                    tx.get('status', 'Unknown')  # Use get() with default value
                ])

            return response

        # Pagination for chain (10 blocks per page)
        paginator = Paginator(filtered_chain, 10)
        page_number = request.GET.get('page', 1)
        try:
            page_obj = paginator.get_page(page_number)
        except Exception as e:
            page_obj = paginator.get_page(1)  # Fallback to first page if invalid

        logger.info(f"Blockchain data retrieved: {len(full_chain)} blocks, {len(pending_transactions)} pending transactions")
        return render(request, 'blockchain.html', {
            'chain': page_obj,
            'pending_transactions': filtered_pending,
            'total_blocks': len(filtered_chain),
            'page_obj': page_obj,
        })
    except Exception as e:
        logger.error(f"Error fetching blockchain data: {str(e)}")
        messages.error(request, "Unable to retrieve blockchain data. Please try again later.")
        return redirect('donations')
    
@login_required
def download_ledger(request):
    full_chain = blockchain.get_chain()
    pending_transactions = blockchain.pending_transactions

    # Normalize transaction data
    for block in full_chain:
        # Parse block timestamp if it's a string
        if isinstance(block.get('timestamp'), str):
            try:
                block['timestamp'] = date_parser.parse(block['timestamp'])
            except ValueError:
                block['timestamp'] = None
        for tx in block.get('transactions', []):
            if not isinstance(tx, dict):
                tx = {
                    'transaction_id': getattr(tx, 'transaction_id', ''),
                    'donor': getattr(tx, 'donor', 'Anonymous'),
                    'email': getattr(tx, 'email', 'N/A'),
                    'amount': getattr(tx, 'amount', '0.00'),
                    'donation_date': getattr(tx, 'donation_date', None),
                    'payment_method': getattr(tx, 'payment_method', 'N/A'),
                    'status': getattr(tx, 'status', 'Unknown')  # Ensure 'status' is always present
                }
            # Align 'date' key to 'donation_date' if present (from blockchain storage)
            if 'date' in tx and 'donation_date' not in tx:
                tx['donation_date'] = tx['date']
            # Ensure donation_date is a date object
            if tx.get('donation_date') and isinstance(tx['donation_date'], str):
                try:
                    tx['donation_date'] = datetime.strptime(tx['donation_date'], '%Y-%m-%d').date()
                except ValueError:
                    tx['donation_date'] = None
            # Parse transaction timestamp if present and it's a string
            if 'timestamp' in tx and isinstance(tx['timestamp'], str):
                try:
                    tx['timestamp'] = date_parser.parse(tx['timestamp'])
                except ValueError:
                    tx['timestamp'] = None
            # Ensure amount is a float
            if 'amount' in tx:
                if isinstance(tx['amount'], str):
                    try:
                        tx['amount'] = float(tx['amount'].replace('₱', '').replace(',', ''))
                    except ValueError:
                        tx['amount'] = 0.0  # Default to 0.0 if conversion fails
                elif tx['amount'] is None:
                    tx['amount'] = 0.0  # Handle None case

    for tx in pending_transactions:
        if not isinstance(tx, dict):
            tx = {
                'transaction_id': getattr(tx, 'transaction_id', ''),
                'donor': getattr(tx, 'donor', 'Anonymous'),
                'email': getattr(tx, 'email', 'N/A'),
                'amount': getattr(tx, 'amount', '0.00'),
                'donation_date': getattr(tx, 'donation_date', None),
                'payment_method': getattr(tx, 'payment_method', 'N/A'),
                'status': getattr(tx, 'status', 'Unknown')  # Ensure 'status' is always present
            }
        # Align 'date' key to 'donation_date' if present (from blockchain storage)
        if 'date' in tx and 'donation_date' not in tx:
            tx['donation_date'] = tx['date']
        # Ensure donation_date is a date object
        if tx.get('donation_date') and isinstance(tx['donation_date'], str):
            try:
                tx['donation_date'] = datetime.strptime(tx['donation_date'], '%Y-%m-%d').date()
            except ValueError:
                tx['donation_date'] = None
        # Parse transaction timestamp if present and it's a string
        if 'timestamp' in tx and isinstance(tx['timestamp'], str):
            try:
                tx['timestamp'] = date_parser.parse(tx['timestamp'])
            except ValueError:
                tx['timestamp'] = None
        # Ensure amount is a float
        if 'amount' in tx:
            if isinstance(tx['amount'], str):
                try:
                    tx['amount'] = float(tx['amount'].replace('₱', '').replace(',', ''))
                except ValueError:
                    tx['amount'] = 0.0  # Default to 0.0 if conversion fails
            elif tx['amount'] is None:
                tx['amount'] = 0.0  # Handle None case

    # Apply filters
    search = request.GET.get('search', '').lower()
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    amount_min = request.GET.get('amount_min', '')  # Default to empty string
    amount_max = request.GET.get('amount_max', '')  # Default to empty string
    status = request.GET.get('status')
    method = request.GET.get('method')

    def matches_filter(tx):
        match = True
        if search and not (tx.get('donor', '').lower().find(search) != -1 or tx.get('transaction_id', '').lower().find(search) != -1):
            match = False
        if date_from and tx.get('donation_date') and tx['donation_date'] < datetime.strptime(date_from, '%Y-%m-%d').date():
            match = False
        if date_to and tx.get('donation_date') and tx['donation_date'] > datetime.strptime(date_to, '%Y-%m-%d').date():
            match = False
        # Convert amount_min and amount_max to float only if they exist and are valid
        if amount_min and amount_min.strip():
            try:
                min_amount = float(amount_min)
                if tx.get('amount', 0) < min_amount:
                    match = False
            except ValueError:
                logger.warning(f"Invalid amount_min: {amount_min}")
                pass  # Ignore invalid input, treat as no filter
        if amount_max and amount_max.strip():
            try:
                max_amount = float(amount_max)
                if tx.get('amount', 0) > max_amount:
                    match = False
            except ValueError:
                logger.warning(f"Invalid amount_max: {amount_max}")
                pass  # Ignore invalid input, treat as no filter
        if status and status != tx.get('status'):
            match = False
        if method and method != tx.get('payment_method'):
            match = False
        return match

    filtered_chain = []
    for block in full_chain:
        filtered_txs = [tx for tx in block.get('transactions', []) if matches_filter(tx)]
        if filtered_txs:
            block_copy = block.copy()
            block_copy['transactions'] = filtered_txs
            filtered_chain.append(block_copy)

    filtered_pending = [tx for tx in pending_transactions if matches_filter(tx)]

    # Generate filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="donation_ledger_{timestamp}.csv"'

    writer = csv.writer(response)
    writer.writerow(['Block Index', 'Timestamp', 'Proof', 'Current Hash', 'Previous Hash', 'Transaction ID', 'Donor', 'Email', 'Amount', 'Date', 'Method', 'Status'])

    for block in filtered_chain:
        for tx in block['transactions']:
            writer.writerow([
                block['index'],
                block['timestamp'],
                block['proof'],
                block['hash'],
                block['previous_hash'],
                tx['transaction_id'],
                tx['donor'],
                tx.get('email', 'N/A'),
                tx['amount'],
                tx.get('donation_date', 'N/A'),
                tx['payment_method'],
                tx.get('status', 'Unknown')  # Use get() with default value
            ])

    writer.writerow([])
    writer.writerow(['Pending Transactions'])
    writer.writerow(['Transaction ID', 'Donor', 'Email', 'Amount', 'Date', 'Method', 'Status'])
    for tx in filtered_pending:
        writer.writerow([
            tx['transaction_id'],
            tx['donor'],
            tx.get('email', 'N/A'),
            tx['amount'],
            tx.get('donation_date', 'N/A'),
            tx['payment_method'],
            tx.get('status', 'Unknown')  # Use get() with default value
        ])

    return response