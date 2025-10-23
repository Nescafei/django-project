"""
Django management command to clean up orphaned media files.
This command can be run periodically (e.g., via cron job or scheduled task) to:
1. Remove QR codes that are older than a specified number of days
2. Remove orphaned media files that no longer have database references
3. Generate a report of cleaned files

Usage:
    python manage.py cleanup_media --qr-age 7 --dry-run
    python manage.py cleanup_media --qr-age 1 --verbose
"""
import os
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.conf import settings
from capstone_project.models import User, ForumMessage, Donation
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Clean up old QR codes and orphaned media files to free up storage space'

    def add_arguments(self, parser):
        parser.add_argument(
            '--qr-age',
            type=int,
            default=7,
            help='Delete QR codes older than this many days (default: 7)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed output',
        )
        parser.add_argument(
            '--check-orphans',
            action='store_true',
            help='Check for and remove orphaned media files (files without database references)',
        )

    def handle(self, *args, **options):
        qr_age_days = options['qr_age']
        dry_run = options['dry_run']
        verbose = options['verbose']
        check_orphans = options['check_orphans']

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No files will be deleted'))

        # Statistics
        stats = {
            'qr_codes_deleted': 0,
            'qr_codes_size': 0,
            'orphaned_profiles': 0,
            'orphaned_profiles_size': 0,
            'orphaned_signatures': 0,
            'orphaned_signatures_size': 0,
            'orphaned_forum_images': 0,
            'orphaned_forum_images_size': 0,
            'orphaned_receipts': 0,
            'orphaned_receipts_size': 0,
        }

        # Clean up old QR codes
        self.stdout.write(f'\nCleaning up QR codes older than {qr_age_days} days...')
        stats = self._cleanup_qr_codes(qr_age_days, dry_run, verbose, stats)

        # Check for orphaned files if requested
        if check_orphans:
            self.stdout.write('\nChecking for orphaned media files...')
            stats = self._cleanup_orphaned_files(dry_run, verbose, stats)

        # Print summary
        self._print_summary(stats, dry_run)

    def _cleanup_qr_codes(self, age_days, dry_run, verbose, stats):
        """Clean up QR codes older than specified days."""
        qr_codes_dir = os.path.join(settings.MEDIA_ROOT, 'qr_codes')
        
        if not os.path.exists(qr_codes_dir):
            self.stdout.write(self.style.WARNING('QR codes directory does not exist'))
            return stats

        cutoff_time = datetime.now() - timedelta(days=age_days)
        
        for filename in os.listdir(qr_codes_dir):
            if filename.startswith('qr_') and filename.endswith('.png'):
                file_path = os.path.join(qr_codes_dir, filename)
                
                try:
                    # Check file modification time
                    file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    if file_mtime < cutoff_time:
                        file_size = os.path.getsize(file_path)
                        
                        if verbose:
                            self.stdout.write(f'  - {filename} (age: {(datetime.now() - file_mtime).days} days, size: {file_size} bytes)')
                        
                        if not dry_run:
                            os.remove(file_path)
                            logger.info(f"Deleted old QR code: {file_path}")
                        
                        stats['qr_codes_deleted'] += 1
                        stats['qr_codes_size'] += file_size
                
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f'Error processing {filename}: {str(e)}'))
                    logger.error(f"Error deleting QR code {file_path}: {str(e)}")

        return stats

    def _cleanup_orphaned_files(self, dry_run, verbose, stats):
        """Check for and remove orphaned media files."""
        
        # Check profile pictures
        stats = self._check_orphaned_in_directory(
            'profile_pics',
            User.objects.exclude(profile_picture='').values_list('profile_picture', flat=True),
            'orphaned_profiles',
            dry_run,
            verbose,
            stats
        )
        
        # Check e-signatures
        stats = self._check_orphaned_in_directory(
            'e_signatures',
            User.objects.exclude(e_signature='').values_list('e_signature', flat=True),
            'orphaned_signatures',
            dry_run,
            verbose,
            stats
        )
        
        # Check forum images
        stats = self._check_orphaned_in_directory(
            'forum_images',
            ForumMessage.objects.exclude(image='').values_list('image', flat=True),
            'orphaned_forum_images',
            dry_run,
            verbose,
            stats
        )
        
        # Check donation receipts
        stats = self._check_orphaned_in_directory(
            'donation_receipts',
            Donation.objects.exclude(receipt='').values_list('receipt', flat=True),
            'orphaned_receipts',
            dry_run,
            verbose,
            stats
        )
        
        return stats

    def _check_orphaned_in_directory(self, dir_name, db_files, stat_prefix, dry_run, verbose, stats):
        """Check a specific directory for orphaned files."""
        dir_path = os.path.join(settings.MEDIA_ROOT, dir_name)
        
        if not os.path.exists(dir_path):
            return stats
        
        # Convert database file paths to just filenames
        db_filenames = set()
        for file_path in db_files:
            if file_path:
                # Extract just the filename from the path
                filename = os.path.basename(file_path)
                db_filenames.add(filename)
        
        self.stdout.write(f'\n  Checking {dir_name}/ (found {len(db_filenames)} files in database)...')
        
        # Check each file in the directory
        for filename in os.listdir(dir_path):
            file_path = os.path.join(dir_path, filename)
            
            # Skip directories
            if os.path.isdir(file_path):
                continue
            
            # Check if file is referenced in database
            if filename not in db_filenames:
                try:
                    file_size = os.path.getsize(file_path)
                    
                    if verbose:
                        self.stdout.write(f'    - Orphaned: {filename} (size: {file_size} bytes)')
                    
                    if not dry_run:
                        os.remove(file_path)
                        logger.info(f"Deleted orphaned file: {file_path}")
                    
                    stats[stat_prefix] += 1
                    stats[f'{stat_prefix}_size'] += file_size
                
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f'    Error processing {filename}: {str(e)}'))
                    logger.error(f"Error deleting orphaned file {file_path}: {str(e)}")
        
        return stats

    def _print_summary(self, stats, dry_run):
        """Print cleanup summary."""
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(self.style.SUCCESS('CLEANUP SUMMARY'))
        self.stdout.write('=' * 60)
        
        total_files = (
            stats['qr_codes_deleted'] +
            stats['orphaned_profiles'] +
            stats['orphaned_signatures'] +
            stats['orphaned_forum_images'] +
            stats['orphaned_receipts']
        )
        
        total_size = (
            stats['qr_codes_size'] +
            stats['orphaned_profiles_size'] +
            stats['orphaned_signatures_size'] +
            stats['orphaned_forum_images_size'] +
            stats['orphaned_receipts_size']
        )
        
        self.stdout.write(f'\nQR Codes:')
        self.stdout.write(f'  Files: {stats["qr_codes_deleted"]}')
        self.stdout.write(f'  Size:  {self._format_size(stats["qr_codes_size"])}')
        
        self.stdout.write(f'\nOrphaned Profile Pictures:')
        self.stdout.write(f'  Files: {stats["orphaned_profiles"]}')
        self.stdout.write(f'  Size:  {self._format_size(stats["orphaned_profiles_size"])}')
        
        self.stdout.write(f'\nOrphaned E-Signatures:')
        self.stdout.write(f'  Files: {stats["orphaned_signatures"]}')
        self.stdout.write(f'  Size:  {self._format_size(stats["orphaned_signatures_size"])}')
        
        self.stdout.write(f'\nOrphaned Forum Images:')
        self.stdout.write(f'  Files: {stats["orphaned_forum_images"]}')
        self.stdout.write(f'  Size:  {self._format_size(stats["orphaned_forum_images_size"])}')
        
        self.stdout.write(f'\nOrphaned Donation Receipts:')
        self.stdout.write(f'  Files: {stats["orphaned_receipts"]}')
        self.stdout.write(f'  Size:  {self._format_size(stats["orphaned_receipts_size"])}')
        
        self.stdout.write('\n' + '-' * 60)
        self.stdout.write(self.style.SUCCESS(f'TOTAL FILES: {total_files}'))
        self.stdout.write(self.style.SUCCESS(f'TOTAL SIZE:  {self._format_size(total_size)}'))
        self.stdout.write('=' * 60 + '\n')
        
        if dry_run:
            self.stdout.write(self.style.WARNING('This was a DRY RUN - no files were actually deleted'))
            self.stdout.write(self.style.WARNING('Run without --dry-run to perform actual cleanup'))

    def _format_size(self, size_bytes):
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
