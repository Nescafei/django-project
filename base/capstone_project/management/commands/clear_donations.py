from django.core.management.base import BaseCommand
from capstone_project.models import Donation
from django.db import connection
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Clears all Donation records from the database.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--noinput',
            action='store_true',
            help='Do not prompt for confirmation before deleting donations.',
        )

    def handle(self, *args, **options):
        noinput = options['noinput']
        
        if not noinput:
            self.stdout.write(
                self.style.WARNING(
                    'This will permanently delete ALL Donation records. Are you sure? (yes/no)'
                )
            )
            confirmation = input().lower()
            if confirmation != 'yes':
                self.stdout.write(self.style.WARNING('Operation cancelled.'))
                return

        try:
            donation_count = Donation.objects.count()
            with connection.cursor() as cursor:
                cursor.execute('DELETE FROM capstone_project_donation')
            logger.info(f'Successfully deleted {donation_count} Donation records.')
            self.stdout.write(
                self.style.SUCCESS(f'Successfully deleted {donation_count} Donation records.')
            )
        except Exception as e:
            logger.error(f'Error deleting Donation records: {str(e)}')
            self.stdout.write(
                self.style.ERROR(f'Error deleting Donation records: {str(e)}')
            )