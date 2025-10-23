# Media Files Cleanup Guide

## Problem
When users upload new profile pictures, e-signatures, or generate QR codes, the old files remain in storage, leading to:
- **Storage bloat** - Accumulation of unused files
- **Increased costs** - Higher storage costs on production servers
- **Performance issues** - Slower backups and file system operations

## Solution Implemented

### 1. Automatic Cleanup via Django Signals

**File:** `capstone_project/signals.py`

Django signals automatically delete old files when:
- A user uploads a new profile picture
- A user uploads a new e-signature
- A forum message image is updated
- A donation receipt is updated
- Any of these records are deleted from the database

**How it works:**
- `pre_save` signals detect when a file field is being updated
- Before saving the new file, the old file is deleted from storage
- `post_delete` signals clean up files when database records are deleted

**Files automatically cleaned:**
- ✅ Profile pictures (`media/profile_pics/`)
- ✅ E-signatures (`media/e_signatures/`)
- ✅ Forum images (`media/forum_images/`)
- ✅ Donation receipts (`media/donation_receipts/`)
- ✅ QR codes (`media/qr_codes/`) - cleaned before generation

### 2. QR Code Cleanup

**Modified:** `capstone_project/views.py` - `member_attend()` function

QR codes are now cleaned up automatically:
- When a user generates a new QR code, their old QR codes are deleted first
- This prevents multiple QR code files per user

### 3. Management Command for Periodic Cleanup

**File:** `capstone_project/management/commands/cleanup_media.py`

A Django management command for periodic maintenance:

```bash
# Dry run - see what would be deleted without actually deleting
python manage.py cleanup_media --dry-run --verbose

# Delete QR codes older than 7 days (default)
python manage.py cleanup_media

# Delete QR codes older than 1 day
python manage.py cleanup_media --qr-age 1

# Check for and remove orphaned files (files without database references)
python manage.py cleanup_media --check-orphans

# Full cleanup with verbose output
python manage.py cleanup_media --qr-age 1 --check-orphans --verbose
```

**Features:**
- Delete QR codes older than specified days
- Find and remove orphaned files (files that exist but have no database reference)
- Dry-run mode to preview changes
- Detailed statistics and reporting
- Safe error handling

## Setup Instructions

### 1. Verify Signal Registration

The signals are automatically registered via `apps.py`. Verify this is in place:

**File:** `capstone_project/apps.py`
```python
def ready(self):
    """Import signal handlers when the app is ready."""
    import capstone_project.signals
```

### 2. Test the Implementation

#### Test Profile Picture Cleanup:
1. Log in as a user
2. Go to Edit Profile
3. Upload a profile picture
4. Note the filename in `media/profile_pics/`
5. Upload a different profile picture
6. Verify the old file is deleted and only the new one exists

#### Test QR Code Cleanup:
1. Log in as a member or officer
2. Generate a QR code for attendance
3. Note the filename in `media/qr_codes/`
4. Generate the QR code again
5. Verify only one QR code file exists for that user

#### Test Management Command:
```bash
# See what would be cleaned (safe to run)
python manage.py cleanup_media --dry-run --verbose --check-orphans
```

### 3. Schedule Periodic Cleanup (Production)

#### Option A: Windows Task Scheduler
1. Open Task Scheduler
2. Create a new task
3. Set trigger (e.g., daily at 2 AM)
4. Set action:
   ```
   Program: C:\path\to\python.exe
   Arguments: manage.py cleanup_media --qr-age 7 --check-orphans
   Start in: C:\path\to\django-project13\base
   ```

#### Option B: Cron Job (Linux)
Add to crontab:
```bash
# Run daily at 2 AM
0 2 * * * cd /path/to/django-project13/base && /path/to/python manage.py cleanup_media --qr-age 7 --check-orphans >> /var/log/media_cleanup.log 2>&1
```

#### Option C: Django-Cron or Celery Beat
For more sophisticated scheduling, consider using:
- `django-cron` package
- `celery` with `celery-beat` for distributed systems

## Monitoring and Maintenance

### Check Cleanup Logs
The cleanup operations are logged. Check your Django logs:
```python
# In settings.py, ensure logging is configured
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'debug.log',
        },
    },
    'loggers': {
        'capstone_project.signals': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
```

### Monthly Audit
Run this command monthly to check for orphaned files:
```bash
python manage.py cleanup_media --check-orphans --dry-run --verbose
```

This will show you:
- How many orphaned files exist
- Total storage being wasted
- Which directories have the most orphaned files

## Storage Savings

Based on typical usage:
- **Profile pictures:** ~50-200 KB each
- **E-signatures:** ~20-100 KB each
- **QR codes:** ~2-5 KB each
- **Forum images:** ~100-500 KB each
- **Donation receipts:** ~100-300 KB each

**Example savings:**
- 100 users changing profile pictures 3 times = ~30-60 MB saved
- 1000 QR code generations = ~10-15 MB saved
- 50 orphaned forum images = ~5-25 MB saved

## Troubleshooting

### Files Not Being Deleted

1. **Check file permissions:**
   - Ensure Django has write/delete permissions on the media directory
   - Windows: Right-click folder → Properties → Security
   - Linux: `chmod -R 755 media/`

2. **Check signals are registered:**
   ```python
   # In Django shell
   python manage.py shell
   >>> from django.db.models.signals import pre_save
   >>> from capstone_project.models import User
   >>> pre_save.receivers
   # Should show signal receivers for User model
   ```

3. **Check logs:**
   - Look for error messages in `debug.log`
   - Check for permission errors or file not found errors

### Orphaned Files Still Exist

Run the cleanup command with `--check-orphans`:
```bash
python manage.py cleanup_media --check-orphans --verbose
```

This will identify and remove files that:
- Were uploaded but the database record was deleted
- Were created by failed upload attempts
- Exist from before the signal implementation

## Best Practices

1. **Always test in development first**
   - Use `--dry-run` flag initially
   - Verify backups are in place

2. **Regular maintenance schedule**
   - Run weekly QR code cleanup
   - Run monthly orphaned file check
   - Monitor storage usage trends

3. **Backup strategy**
   - Keep database backups separate from media files
   - Consider archiving old media files before deletion
   - Test restore procedures

4. **Monitor storage metrics**
   - Track media directory size over time
   - Set up alerts for unusual growth
   - Review cleanup logs regularly

## Additional Notes

### QR Code Lifecycle
QR codes are temporary by design:
- Generated on-demand for attendance
- Typically only needed for a few hours/days
- Safe to delete after 7 days (default)
- Can be regenerated anytime

### Profile Picture Versions
The signals only keep the latest version:
- Old versions are immediately deleted
- No version history is maintained
- Users can always upload a new picture

### Safety Features
- All deletions are logged
- Dry-run mode available for testing
- Only deletes files, never database records
- Graceful error handling prevents crashes

## Support

If you encounter issues:
1. Check the logs in `debug.log`
2. Run cleanup with `--dry-run --verbose` to diagnose
3. Verify file permissions
4. Ensure signals are properly registered in `apps.py`

---

**Last Updated:** 2025-10-04  
**Django Version:** 4.x+  
**Python Version:** 3.8+
