import uuid
import logging
import hashlib
from datetime import date
from decimal import Decimal
from django.test import TestCase
from django.utils import timezone
from django.core.exceptions import ValidationError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from capstone_project.models import Blockchain, Block, Donation, Council, User
from capstone_project.more_views import PRIVATE_KEY, PUBLIC_KEY

logger = logging.getLogger(__name__)

class BlockchainTests(TestCase):
    def setUp(self):
        """Set up test environment with blockchain, council, user, and donations."""
        # Create council
        self.council = Council.objects.create(id=1, name="Test Council", district="Test District")
        
        # Create admin user
        self.user = User.objects.create_user(
            username="test_admin",
            password="testpass123",
            role="admin",
            council=self.council
        )
        
        # Initialize blockchain
        Blockchain.objects.all().delete()
        Block.objects.all().delete()
        Donation.objects.all().delete()
        self.blockchain = Blockchain.objects.create(pending_transactions=[])
        self.blockchain.initialize_chain()
        
        # Create donations
        self.donation1 = Donation.objects.create(
            transaction_id=f"GCASH-{uuid.uuid4().hex[:8]}",
            first_name="John",
            middle_initial="D",
            last_name="Doe",
            email="john.doe@example.com",
            amount=Decimal('1000.00'),
            donation_date=date.today(),
            payment_method='gcash',
            status='completed',
            source_id="test_source_1",
            submitted_by=self.user
        )
        self.donation1.sign_donation(PRIVATE_KEY)
        self.donation1.save()
        
        self.donation2 = Donation.objects.create(
            transaction_id=f"GCASH-{uuid.uuid4().hex[:8]}",
            first_name="Jane",
            middle_initial="E",
            last_name="Smith",
            email="jane.smith@example.com",
            amount=Decimal('500.00'),
            donation_date=date.today(),
            payment_method='gcash',
            status='completed',
            source_id="test_source_2",
            submitted_by=self.user
        )
        self.donation2.sign_donation(PRIVATE_KEY)
        self.donation2.save()
        
        # Add donations to blockchain
        self.blockchain.add_transaction(self.donation1, PUBLIC_KEY)
        previous_block = self.blockchain.get_previous_block()
        proof = self.blockchain.proof_of_work(previous_block['proof'])
        self.blockchain.create_block(proof)
        
        self.blockchain.add_transaction(self.donation2, PUBLIC_KEY)
        previous_block = self.blockchain.get_previous_block()
        proof = self.blockchain.proof_of_work(previous_block['proof'])
        self.blockchain.create_block(proof)
        
        logger.info("Test setup complete: 2 donations, 3 blocks (genesis + 2)")

    def test_immutability_block_modification(self):
        """Test that blocks cannot be modified due to block_pre_save."""
        block = Block.objects.get(index=2)
        original_hash = block.hash
        with self.assertRaises(ValidationError) as context:
            block.transactions = []  # Attempt to tamper
            block.save()
        self.assertEqual(str(context.exception.messages[0]), "Block modifications are not allowed")
        self.assertTrue(self.blockchain.is_chain_valid())
        logger.info("Immutability test passed: Block modification blocked")

    def test_immutability_hash_chain(self):
        """Test that tampering with a block invalidates the chain."""
        block = Block.objects.get(index=2)
        original_hash = block.hash
        original_transactions = block.transactions
        # Disconnect block_pre_save
        from django.db.models.signals import pre_save
        from capstone_project.models import block_pre_save
        pre_save.disconnect(block_pre_save, sender=Block)
        block.transactions = []  # Tamper
        block.hash = block.calculate_hash()  # Recalculate hash
        block.save()
        self.assertFalse(self.blockchain.is_chain_valid())
        logger.info(f"Immutability test passed: Tampered block hash={block.hash}, chain invalid")
        # Restore block
        block.transactions = original_transactions
        block.hash = original_hash
        block.save()
        # Reconnect block_pre_save
        pre_save.connect(block_pre_save, sender=Block)
        self.assertTrue(self.blockchain.is_chain_valid())

    def test_untamperability_donation(self):
        """Test that modifying a donation invalidates its signature."""
        donation = Donation.objects.get(transaction_id=self.donation1.transaction_id)
        self.assertTrue(donation.verify_signature(PUBLIC_KEY))
        donation.amount = Decimal('2000.00')  # Tamper
        donation.save()
        self.assertFalse(donation.verify_signature(PUBLIC_KEY))
        logger.info("Untamperability test passed: Signature invalid after tampering")

    def test_data_integrity(self):
        """Test that the blockchain maintains hash links and proof-of-work."""
        self.assertTrue(self.blockchain.is_chain_valid())
        chain = self.blockchain.get_chain()
        self.assertEqual(len(chain), 3)  # Genesis + 2 blocks
        for i in range(1, len(chain)):
            self.assertEqual(chain[i]['previous_hash'], chain[i-1]['hash'])
            hash_operation = hashlib.sha256(
                str(chain[i]['proof']**2 - chain[i-1]['proof']**2).encode()
            ).hexdigest()
            self.assertTrue(hash_operation.startswith('0000'))
        logger.info("Data integrity test passed: Hash links and proof-of-work valid")

    def test_signature_keys(self):
        """Test that donations are signed and signatures are verifiable."""
        donation = Donation.objects.get(transaction_id=self.donation2.transaction_id)
        self.assertTrue(donation.verify_signature(PUBLIC_KEY))
        # Create a new key pair to test invalid public key
        invalid_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        invalid_public_key = invalid_private_key.public_key()
        self.assertFalse(donation.verify_signature(invalid_public_key))
        logger.info("Signature keys test passed: Valid signature verified, invalid key rejected")

    def test_blockchain_donation_flow(self):
        """Test the full donation-to-blockchain flow."""
        donation = Donation.objects.create(
            transaction_id=f"GCASH-{uuid.uuid4().hex[:8]}",
            first_name="Alice",
            middle_initial="F",
            last_name="Brown",
            email="alice.brown@example.com",
            amount=Decimal('750.00'),
            donation_date=date.today(),
            payment_method='gcash',
            status='completed',
            source_id="test_source_3",
            submitted_by=self.user
        )
        donation.sign_donation(PRIVATE_KEY)
        donation.save()
        self.assertTrue(donation.verify_signature(PUBLIC_KEY))
        
        self.blockchain.add_transaction(donation, PUBLIC_KEY)
        previous_block = self.blockchain.get_previous_block()
        proof = self.blockchain.proof_of_work(previous_block['proof'])
        block = self.blockchain.create_block(proof)
        
        self.assertTrue(self.blockchain.is_chain_valid())
        chain = self.blockchain.get_chain()
        self.assertEqual(len(chain), 4)  # Genesis + 3 blocks
        expected_transaction = {
            'transaction_id': donation.transaction_id,
            'donor': f"{donation.first_name} {donation.last_name}",
            'email': donation.email,
            'amount': str(donation.amount),
            'date': donation.donation_date.isoformat(),
            'payment_method': donation.payment_method,
        }
        block_transactions = [
            {k: v for k, v in tx.items() if k != 'timestamp'}
            for tx in chain[-1]['transactions']
        ]
        self.assertIn(expected_transaction, block_transactions)
        logger.info("Donation flow test passed: Donation recorded on blockchain")