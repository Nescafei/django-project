from django.core.management.base import BaseCommand
from capstone_project.models import blockchain, Block, Donation
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Tests the blockchain-driven donation system'

    def handle(self, *args, **kwargs):
        self.stdout.write('Testing Blockchain System...\n')
        
        # Test 1: Check blockchain validity
        self.stdout.write('Test 1: Checking blockchain validity...')
        is_valid = blockchain.is_chain_valid()
        self.stdout.write(f'Blockchain is {"VALID" if is_valid else "INVALID"}\n')
        
        # Test 2: Check block structure
        self.stdout.write('Test 2: Checking block structure...')
        chain = blockchain.get_chain()
        self.stdout.write(f'Number of blocks: {len(chain)}')
        for block in chain:
            self.stdout.write(f'Block {block["index"]}:')
            self.stdout.write(f'  - Hash: {block["current_hash"]}')
            self.stdout.write(f'  - Previous Hash: {block["previous_hash"]}')
            self.stdout.write(f'  - Transactions: {len(block["transactions"])}')
            self.stdout.write(f'  - Proof: {block["proof"]}\n')
        
        # Test 3: Check pending transactions
        self.stdout.write('Test 3: Checking pending transactions...')
        pending = blockchain.pending_transactions
        self.stdout.write(f'Number of pending transactions: {len(pending)}\n')
        
        # Test 4: Check block linking
        self.stdout.write('Test 4: Checking block linking...')
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i-1]
            if current_block['previous_hash'] == previous_block['current_hash']:
                self.stdout.write(f'Block {current_block["index"]} correctly links to Block {previous_block["index"]}')
            else:
                self.stdout.write(self.style.ERROR(f'Block {current_block["index"]} has incorrect previous hash!'))
        self.stdout.write('')
        
        # Test 5: Check proof of work
        self.stdout.write('Test 5: Checking proof of work...')
        for block in chain:
            if block['index'] > 1:  # Skip genesis block
                previous_block = chain[block['index']-2]
                hash_operation = f"{block['proof']**2 - previous_block['proof']**2}"
                if hash_operation.startswith('000000'):
                    self.stdout.write(f'Block {block["index"]} has valid proof of work')
                else:
                    self.stdout.write(self.style.ERROR(f'Block {block["index"]} has invalid proof of work!'))
        self.stdout.write('')
        
        # Test 6: Check transaction integrity
        self.stdout.write('Test 6: Checking transaction integrity...')
        for block in chain:
            if block['transactions']:
                self.stdout.write(f'Block {block["index"]} contains {len(block["transactions"])} transactions')
                for tx in block['transactions']:
                    self.stdout.write(f'  - Transaction ID: {tx["transaction_id"]}')
                    self.stdout.write(f'    Amount: {tx["amount"]}')
                    self.stdout.write(f'    Status: {tx["status"]}')
        self.stdout.write('')
        
        self.stdout.write(self.style.SUCCESS('Blockchain testing completed!')) 