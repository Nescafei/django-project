from capstone_project.models import blockchain
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.views.decorators.cache import never_cache
from django.core.paginator import Paginator
from django.contrib import messages
from datetime import datetime, date
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font
from openpyxl.utils import get_column_letter
import io
import logging
import csv
from dateutil import parser as date_parser

logger = logging.getLogger(__name__)

def mask_name(name):
    """Partially mask a name for privacy: reveal first/last letter per word (>2 chars), star middle."""
    if not name:
        return 'N/A'
    parts = name.split()
    masked_parts = []
    for part in parts:
        if len(part) <= 2:
            masked_parts.append(part)  # Keep short parts/initials as-is
        else:
            middle_len = len(part) - 2
            masked_parts.append(part[0] + '*' * middle_len + part[-1])
    return ' '.join(masked_parts)

def mask_email(email):
    """Partially mask email local part: reveal first/last, star middle; keep domain."""
    if not email or '@' not in email:
        return 'N/A'
    local, domain = email.split('@', 1)
    if len(local) <= 2:
        masked_local = local
    else:
        middle_len = len(local) - 2
        masked_local = local[0] + '*' * middle_len + local[-1]
    return masked_local + '@' + domain

def normalize_blockchain_data(full_chain, pending_transactions):
    # === RESTORED ORIGINAL FULL NORMALIZATION (this was the part that broke timestamps/dates) ===
    for block in full_chain:
        if not isinstance(block, dict):
            block = {
                'index': block.index,
                'timestamp': block.timestamp,
                'transactions': block.transactions if hasattr(block, 'transactions') else [],
                'proof': block.proof,
                'previous_hash': block.previous_hash,
                'hash': block.hash
            }
        # Parse block timestamp if it's a string
        if isinstance(block.get('timestamp'), str):
            try:
                block['timestamp'] = date_parser.parse(block['timestamp'])
            except ValueError:
                block['timestamp'] = None
        for tx in block.get('transactions', []):
            if not isinstance(tx, dict):
                is_anonymous = getattr(tx, 'is_anonymous', False)
                donor = tx.get_display_name() if hasattr(tx, 'get_display_name') else getattr(tx, 'donor', 'Anonymous')
                email = getattr(tx, 'email', 'N/A')
                tx = {
                    'transaction_id': getattr(tx, 'transaction_id', ''),
                    'donor': donor,
                    'email': email,
                    'amount': getattr(tx, 'amount', '0.00'),
                    'donation_date': getattr(tx, 'donation_date', None),
                    'payment_method': getattr(tx, 'payment_method', 'N/A'),
                    'is_anonymous': is_anonymous
                }
            else:
                is_anonymous = tx.get('is_anonymous', False)
            # Mask personal details
            if tx.get('is_anonymous', False):
                tx['donor'] = "Anonymous Donor"
                tx['email'] = "N/A"
            else:
                # Partial mask for non-anonymous
                tx['donor'] = mask_name(tx.get('donor', ''))
                tx['email'] = mask_email(tx.get('email', ''))
            # Align 'date' key to 'donation_date' if present
            if 'date' in tx and 'donation_date' not in tx:
                tx['donation_date'] = tx['date']
            # Ensure donation_date is a date object
            if tx.get('donation_date') and isinstance(tx.get('donation_date'), str):
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
                        tx['amount'] = 0.0
                elif tx['amount'] is None:
                    tx['amount'] = 0.0

    # Same detailed normalization for pending_transactions
    for tx in pending_transactions:
        if not isinstance(tx, dict):
            is_anonymous = getattr(tx, 'is_anonymous', False)
            donor = tx.get_display_name() if hasattr(tx, 'get_display_name') else getattr(tx, 'donor', 'Anonymous')
            email = getattr(tx, 'email', 'N/A')
            tx = {
                'transaction_id': getattr(tx, 'transaction_id', ''),
                'donor': donor,
                'email': email,
                'amount': getattr(tx, 'amount', '0.00'),
                'donation_date': getattr(tx, 'donation_date', None),
                'payment_method': getattr(tx, 'payment_method', 'N/A'),
                'is_anonymous': is_anonymous
            }
        else:
            is_anonymous = tx.get('is_anonymous', False)
        if tx.get('is_anonymous', False):
            tx['donor'] = "Anonymous Donor"
            tx['email'] = "N/A"
        else:
            tx['donor'] = mask_name(tx.get('donor', ''))
            tx['email'] = mask_email(tx.get('email', ''))
        if 'date' in tx and 'donation_date' not in tx:
            tx['donation_date'] = tx['date']
        if tx.get('donation_date') and isinstance(tx['donation_date'], str):
            try:
                tx['donation_date'] = datetime.strptime(tx['donation_date'], '%Y-%m-%d').date()
            except ValueError:
                tx['donation_date'] = None
        if 'timestamp' in tx and isinstance(tx['timestamp'], str):
            try:
                tx['timestamp'] = date_parser.parse(tx['timestamp'])
            except ValueError:
                tx['timestamp'] = None
        if 'amount' in tx:
            if isinstance(tx['amount'], str):
                try:
                    tx['amount'] = float(tx['amount'].replace('₱', '').replace(',', ''))
                except ValueError:
                    tx['amount'] = 0.0
            elif tx['amount'] is None:
                tx['amount'] = 0.0

    return full_chain, pending_transactions

def get_matches_filter(search, date_from, date_to, amount_min, amount_max, method):
    def matches_filter(tx):
        match = True
        if search and not (search.lower() in tx.get('donor', '').lower() or search.lower() in tx.get('transaction_id', '').lower()):
            match = False
        if date_from and tx.get('donation_date') and tx['donation_date'] < datetime.strptime(date_from, '%Y-%m-%d').date():
            match = False
        if date_to and tx.get('donation_date') and tx['donation_date'] > datetime.strptime(date_to, '%Y-%m-%d').date():
            match = False
        if amount_min and amount_min.strip():
            try:
                if tx.get('amount', 0) < float(amount_min):
                    match = False
            except ValueError:
                pass
        if amount_max and amount_max.strip():
            try:
                if tx.get('amount', 0) > float(amount_max):
                    match = False
            except ValueError:
                pass
        if method and method != tx.get('payment_method'):
            match = False
        return match
    return matches_filter

@never_cache
@login_required
def get_blockchain_data(request):
    try:
        full_chain = blockchain.get_chain()
        if not blockchain.is_chain_valid():
            messages.error(request, "Blockchain data is corrupted. Contact support.")
            return redirect('donations')
        
        pending_transactions = blockchain.pending_transactions

        # Full original normalization restored → fixes timestamp/date N/A bug
        full_chain, pending_transactions = normalize_blockchain_data(full_chain, pending_transactions)

        # Filters
        search = request.GET.get('search', '').lower()
        date_from = request.GET.get('date_from')
        date_to = request.GET.get('date_to')
        amount_min = request.GET.get('amount_min', '')
        amount_max = request.GET.get('amount_max', '')
        method = request.GET.get('method')

        matches_filter_func = get_matches_filter(search, date_from, date_to, amount_min, amount_max, method)

        # Filter blocks that have at least one matching tx
        filtered_chain = []
        for block in full_chain:
            filtered_txs = [tx for tx in block.get('transactions', []) if matches_filter_func(tx)]
            if filtered_txs:
                block_copy = block.copy()
                block_copy['transactions'] = filtered_txs
                filtered_chain.append(block_copy)

        filtered_pending = [tx for tx in pending_transactions if matches_filter_func(tx)]

        # === FLATTEN WITH PROPER SORT KEY (pending = newest) ===
        all_transactions = []
        max_block_index = max((b.get('index', 0) for b in full_chain), default=0)

        # Confirmed transactions
        for block in filtered_chain:
            for tx in block.get('transactions', []):
                tx_copy = tx.copy()
                tx_copy['block_index'] = block['index']
                tx_copy['block_timestamp'] = block['timestamp']
                tx_copy['_sort_key'] = block['index']
                all_transactions.append(tx_copy)

        # Pending transactions (treated as newest)
        for tx in filtered_pending:
            tx_copy = tx.copy()
            tx_copy['block_index'] = None
            tx_copy['block_timestamp'] = None
            tx_copy['_sort_key'] = max_block_index + 1
            all_transactions.append(tx_copy)

        # === SORTING ===
        sort = request.GET.get('sort', 'recent_to_oldest')
        if sort == 'recent_to_oldest':
            all_transactions.sort(key=lambda x: x['_sort_key'], reverse=True)
        elif sort == 'oldest_to_recent':
            all_transactions.sort(key=lambda x: x['_sort_key'])
        elif sort == 'highest_amount':
            all_transactions.sort(key=lambda x: x.get('amount', 0), reverse=True)
        elif sort == 'lowest_amount':
            all_transactions.sort(key=lambda x: x.get('amount', 0))

        total_transactions = len(all_transactions)

        paginator = Paginator(all_transactions, 10)
        page_number = request.GET.get('page', 1)
        page_obj = paginator.get_page(page_number)

        return render(request, 'blockchain.html', {
            'all_transactions': all_transactions,  # not needed anymore but safe
            'page_obj': page_obj,
            'total_blocks': len(filtered_chain),
            'total_transactions': total_transactions,
            'pending_transactions': filtered_pending,
        })
    except Exception as e:
        logger.error(f"Error fetching blockchain data: {str(e)}")
        messages.error(request, "Unable to retrieve blockchain data.")
        return redirect('donations')

@login_required
def download_ledger(request):
    # === SAME DATA PREPARATION AS BEFORE (filtering + sorting) ===
    full_chain = blockchain.get_chain()
    pending_transactions = blockchain.pending_transactions
    full_chain, pending_transactions = normalize_blockchain_data(full_chain, pending_transactions)

    search = request.GET.get('search', '').lower()
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    amount_min = request.GET.get('amount_min', '')
    amount_max = request.GET.get('amount_max', '')
    method = request.GET.get('method')

    matches_filter_func = get_matches_filter(search, date_from, date_to, amount_min, amount_max, method)

    filtered_chain = []
    for block in full_chain:
        filtered_txs = [tx for tx in block.get('transactions', []) if matches_filter_func(tx)]
        if filtered_txs:
            block_copy = block.copy()
            block_copy['transactions'] = filtered_txs
            filtered_chain.append(block_copy)

    filtered_pending = [tx for tx in pending_transactions if matches_filter_func(tx)]

    all_transactions = []
    max_block_index = max((b.get('index', 0) for b in full_chain), default=0)

    for block in filtered_chain:
        for tx in block.get('transactions', []):
            tx_copy = tx.copy()
            tx_copy['block_index'] = block['index']
            tx_copy['block_timestamp'] = block['timestamp']
            all_transactions.append(tx_copy)

    for tx in filtered_pending:
        tx_copy = tx.copy()
        tx_copy['block_index'] = None
        tx_copy['block_timestamp'] = None
        all_transactions.append(tx_copy)

    sort = request.GET.get('sort', 'recent_to_oldest')
    if sort == 'recent_to_oldest':
        all_transactions.sort(key=lambda x: x.get('block_index', max_block_index + 1), reverse=True)
    elif sort == 'oldest_to_recent':
        all_transactions.sort(key=lambda x: x.get('block_index', max_block_index + 1))
    elif sort == 'highest_amount':
        all_transactions.sort(key=lambda x: x.get('amount', 0), reverse=True)
    elif sort == 'lowest_amount':
        all_transactions.sort(key=lambda x: x.get('amount', 0))

    # === EXCEL (.XLSX) EXPORT WITH PERFECT FORMATTING ===
    wb = Workbook()
    ws = wb.active
    ws.title = "Donation Ledger"

    # Headers
    headers = ['Block Index', 'Block Timestamp', 'Transaction ID', 'Donor', 'Email', 'Amount', 'Date', 'Method']
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    # Add data rows
    for tx in all_transactions:
        donation_date = tx.get('donation_date')
        if isinstance(donation_date, str):
            try:
                donation_date = datetime.strptime(donation_date, '%Y-%m-%d').date()
            except:
                donation_date = None

        amount = float(tx.get('amount', 0)) if tx.get('amount') not in (None, '') else 0.0
        block_timestamp = tx.get('block_timestamp')
        if block_timestamp and block_timestamp.tzinfo is not None:
            block_timestamp = block_timestamp.replace(tzinfo=None)

        donation_date = tx.get('donation_date')
        if donation_date and hasattr(donation_date, 'tzinfo') and donation_date.tzinfo is not None:
            donation_date = donation_date.replace(tzinfo=None)
        ws.append([
            tx.get('block_index', 'Pending') if tx.get('block_index') is not None else 'Pending',
            block_timestamp if block_timestamp else '',  # ← now timezone-naive or empty
            tx.get('transaction_id', ''),
            tx.get('donor', 'N/A'),
            tx.get('email', 'N/A'),
            amount,
            donation_date,  # ← safe now
            tx.get('payment_method', 'N/A')
        ])

    # Styling: wrap text + auto-size columns
    wrap_alignment = Alignment(wrap_text=True, vertical='top')

    for row in ws.iter_rows(min_row=2, max_row=ws.max_row):
        for cell in row:
            cell.alignment = wrap_alignment

    # Format specific columns
    # Amount → ₱ currency
    for cell in ws['F'][1:]:
        cell.number_format = '"₱"#,##0.00'

    # Date → real date
    for cell in ws['G'][1:]:
        if cell.value:
            cell.number_format = 'YYYY-MM-DD'

    # Timestamp → datetime
    for cell in ws['B'][1:]:
        if cell.value:
            cell.number_format = 'YYYY-MM-DD HH:MM:SS'

    # Auto-size all columns based on content
    for column_cells in ws.columns:
        length = max(len(str(cell.value)) for cell in column_cells if cell.value)
        length = min(length + 4, 60)  # cap at 60 to avoid huge sheets
        ws.column_dimensions[get_column_letter(column_cells[0].column)].width = length

    # Force minimum widths for long text columns
    ws.column_dimensions['D'].width = 35  # Donor
    ws.column_dimensions['C'].width = 28  # Transaction ID
    ws.column_dimensions['E'].width = 32  # Email

    # Output to response
    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    response = HttpResponse(
        output,
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename="donation_ledger_{timestamp}.xlsx"'
    return response