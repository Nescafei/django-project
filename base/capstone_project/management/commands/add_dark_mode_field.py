"""
Management command to add dark_mode field to User model if it doesn't exist
Run with: python manage.py add_dark_mode_field
"""
from django.core.management.base import BaseCommand
from django.db import connection
from capstone_project.models import User

class Command(BaseCommand):
    help = 'Add dark_mode field to User model if it does not exist'

    def handle(self, *args, **options):
        with connection.cursor() as cursor:
            # Check if dark_mode column exists
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='capstone_project_user' 
                AND column_name='dark_mode'
            """)
            
            if cursor.fetchone():
                self.stdout.write(self.style.SUCCESS('dark_mode column already exists'))
                return
            
            # Add the column if it doesn't exist
            try:
                cursor.execute("""
                    ALTER TABLE capstone_project_user 
                    ADD COLUMN dark_mode BOOLEAN DEFAULT FALSE
                """)
                self.stdout.write(self.style.SUCCESS('Successfully added dark_mode column to User model'))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Error adding dark_mode column: {str(e)}'))
