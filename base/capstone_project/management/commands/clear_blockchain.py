from django.core.management.base import BaseCommand
from capstone_project.models import Block
from django.db import connection
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Clears all Block records from the blockchain database.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--noinput',
            action='store_true',
            help='Do not prompt for confirmation before deleting blockchain records.',
        )

    def handle(self, *args, **options):
        noinput = options['noinput']
        
        if not noinput:
            self.stdout.write(
                self.style.WARNING(
                    'This will permanently delete ALL Block records in the blockchain. Are you sure? (yes/no)'
                )
            )
            confirmation = input().lower()
            if confirmation != 'yes':
                self.stdout.write(self.style.WARNING('Operation cancelled.'))
                return

        try:
            block_count = Block.objects.count()
            with connection.cursor() as cursor:
                cursor.execute('DELETE FROM capstone_project_block')
            logger.info(f'Successfully deleted {block_count} Block records.')
            self.stdout.write(
                self.style.SUCCESS(f'Successfully deleted {block_count} Block records.')
            )
        except Exception as e:
            logger.error(f'Error deleting Block records: {str(e)}')
            self.stdout.write(
                self.style.ERROR(f'Error deleting Block records: {str(e)}')
            )