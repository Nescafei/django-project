# Quick Start: Media Cleanup Solution

## ✅ What Was Implemented

Your Django application now automatically cleans up old media files to prevent storage bloat!

## 🎯 Files Modified/Created

### Created:
1. **`capstone_project/signals.py`** - Automatic file deletion on upload/update
2. **`capstone_project/management/commands/cleanup_media.py`** - Periodic cleanup command
3. **`MEDIA_CLEANUP_GUIDE.md`** - Complete documentation

### Modified:
1. **`capstone_project/apps.py`** - Registered signal handlers
2. **`capstone_project/views.py`** - Added QR code cleanup in `member_attend()`

## 🚀 How It Works

### Automatic Cleanup (Real-time)
When a user uploads a new file, the old one is **automatically deleted**:
- ✅ Profile pictures
- ✅ E-signatures  
- ✅ Forum images
- ✅ Donation receipts
- ✅ QR codes (before generation)

**No action needed** - this happens automatically!

### Manual Cleanup (Periodic)
Run this command to clean up old files:

```bash
# Safe preview (recommended first time)
python manage.py cleanup_media --dry-run --verbose

# Delete QR codes older than 7 days
python manage.py cleanup_media

# Full cleanup including orphaned files
python manage.py cleanup_media --qr-age 1 --check-orphans
```

## 🧪 Test It Now

### Test 1: Profile Picture Cleanup
1. Log in to your application
2. Go to Edit Profile
3. Upload a profile picture
4. Check `base/media/profile_pics/` - note the filename
5. Upload a **different** profile picture
6. Check the folder again - **old file should be gone!**

### Test 2: QR Code Cleanup  
1. Log in as a member/officer
2. Generate attendance QR code
3. Check `base/media/qr_codes/` - note the filename
4. Generate QR code again
5. Check the folder - **only one QR code per user!**

### Test 3: Management Command
```bash
cd base
python manage.py cleanup_media --dry-run --verbose --check-orphans
```
This shows what would be cleaned without actually deleting anything.

## 📊 Expected Results

### Before Implementation:
```
media/
├── profile_pics/
│   ├── user1_profile.jpg
│   ├── user1_profile_abc123.jpg  ← Old version (wasted space)
│   ├── user1_profile_def456.jpg  ← Old version (wasted space)
│   └── user1_profile_ghi789.jpg  ← Current version
└── qr_codes/
    ├── qr_1_John_Doe.png
    ├── qr_1_John_Doe_old.png      ← Old version (wasted space)
    └── qr_1_John_Doe_older.png    ← Old version (wasted space)
```

### After Implementation:
```
media/
├── profile_pics/
│   └── user1_profile.jpg          ← Only current version!
└── qr_codes/
    └── qr_1_John_Doe.png          ← Only current version!
```

## 🔧 Production Setup

### Option 1: Windows Task Scheduler (Recommended for Windows)
1. Open **Task Scheduler**
2. Create Basic Task → Name it "Django Media Cleanup"
3. Trigger: **Daily at 2:00 AM**
4. Action: **Start a program**
   - Program: `C:\path\to\python.exe`
   - Arguments: `manage.py cleanup_media --qr-age 7`
   - Start in: `C:\Users\ianmi\Documents\Capsie\3\django-project13\django-project13\base`

### Option 2: Manual Weekly Run
Set a reminder to run this weekly:
```bash
python manage.py cleanup_media --qr-age 7 --check-orphans
```

## 📈 Storage Savings

Based on your current media files:
- **Profile pictures:** ~16 files found
- **E-signatures:** ~16 files found  
- **Forum images:** ~7 files found

**Potential savings:** If users have uploaded 2-3 versions each, you could save **10-50 MB** immediately!

## ⚠️ Important Notes

1. **Automatic cleanup is now active** - Old files will be deleted when new ones are uploaded
2. **QR codes are temporary** - They're regenerated each time, so old ones can be safely deleted
3. **Run the management command periodically** to catch any orphaned files
4. **Always use `--dry-run` first** when testing the cleanup command

## 🆘 Troubleshooting

### Files not being deleted?
```bash
# Check if signals are working
python manage.py shell
>>> from capstone_project.signals import delete_old_profile_picture
>>> print("Signals loaded successfully!")
```

### Want to see what would be cleaned?
```bash
python manage.py cleanup_media --dry-run --verbose --check-orphans
```

### Check the logs
Look at `debug.log` for cleanup activity:
```
Deleted old profile picture: /path/to/old_file.jpg
Deleted old QR code: /path/to/old_qr.png
```

## 📚 Full Documentation

See **`MEDIA_CLEANUP_GUIDE.md`** for:
- Detailed technical explanation
- Advanced configuration options
- Monitoring and maintenance procedures
- Troubleshooting guide

## ✨ Summary

**You're all set!** Your application will now:
- ✅ Automatically delete old files when users upload new ones
- ✅ Clean up QR codes before generating new ones
- ✅ Provide a command to remove orphaned files periodically

**Next Steps:**
1. Test the automatic cleanup (upload a new profile picture)
2. Run the cleanup command: `python manage.py cleanup_media --dry-run --verbose`
3. Schedule periodic cleanup in production (Windows Task Scheduler)

---

**Questions?** Check `MEDIA_CLEANUP_GUIDE.md` or review the code in `capstone_project/signals.py`
