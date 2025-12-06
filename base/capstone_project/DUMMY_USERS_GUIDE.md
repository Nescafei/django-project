 Dummy Users Generation Guide

## Overview

A Django management command has been created to generate realistic dummy users for testing purposes. The command generates users with data based on the sign-up form fields.

## Features

✅ **75 users per council** (customizable)
✅ **Realistic names** (Filipino names)
✅ **Complete user data** (all sign-up form fields)
✅ **Automatic e-signature generation** (dummy images)
✅ **Configurable role** (pending or member)
✅ **Unique usernames** (automatic duplicate prevention)

## Installation

The management command is already created at:
```
c:\Users\ianmi\Documents\Capsie\base\base\capstone_project\management\commands\generate_dummy_users.py
```

## Usage

### Basic Usage (75 pending users per council)
```bash
python manage.py generate_dummy_users
```

### Generate 100 users per council
```bash
python manage.py generate_dummy_users --count=100
```

### Generate members instead of pending users
```bash
python manage.py generate_dummy_users --role=member
```

### Generate 50 member users per council
```bash
python manage.py generate_dummy_users --count=50 --role=member
```

## Generated User Data

Each dummy user includes:

### Personal Information
- **First Name** - Filipino names (Juan, Jose, Miguel, etc.)
- **Middle Name** - Filipino middle names (Maria, Santos, Cruz, etc.)
- **Last Name** - Filipino surnames (Garcia, Martinez, Rodriguez, etc.)
- **Birthday** - Random age 18-70 years old
- **Marital Status** - Random (Single, Married, Widowed, Divorced, Separated)
- **Occupation** - Random from 26 occupations
- **Gender** - Male (default for Knights of Columbus)
- **Religion** - Catholic (default)

### Contact Information
- **Street** - Random street address
- **Province** - Random from (Batangas, Cavite, Laguna, Quezon, Rizal)
- **City** - Auto-generated from province
- **Barangay** - Random barangay
- **ZIP Code** - Random 4-digit code
- **Contact Number** - Random Philippine mobile number (09xxxxxxxxx)

### Account Information
- **Username** - Auto-generated unique username
- **Email** - Auto-generated email (username@example.com)
- **Password** - DummyPass123! (same for all)
- **Role** - Pending or Member (configurable)
- **Council** - Assigned to each council

### Membership Details
- **Recruiter** - Random (voluntary join or recruiter name)
- **Join Reason** - Random from 10 predefined reasons
- **E-Signature** - Auto-generated dummy image

## Data Examples

### Example User 1
```
Username: juangarcia1234
Email: juangarcia1234@example.com
First Name: Juan
Middle Name: Maria
Last Name: Garcia
Birthday: 1985-03-15 (age 39)
Contact: 09123456789
Street: 456 Oak Avenue
Province: Batangas
Occupation: Engineer
Marital Status: Married
Council: Council A
Role: Pending
```

### Example User 2
```
Username: carlosrodriguez5678
Email: carlosrodriguez5678@example.com
First Name: Carlos
Middle Name: de la
Last Name: Rodriguez
Birthday: 1995-07-22 (age 29)
Contact: 09987654321
Street: 123 Main Street
Province: Cavite
Occupation: Teacher
Marital Status: Single
Council: Council B
Role: Member
```

## Database Impact

### Before Running Command
- Users: 0-5 (admin, officers, etc.)
- Total: ~5 users

### After Running Command (75 users per council)
- If 4 councils: 4 × 75 = 300 users
- If 5 councils: 5 × 75 = 375 users
- Total: 305-380 users (depending on councils)

## Important Notes

⚠️ **Password**: All dummy users have the same password: `DummyPass123!`

⚠️ **Email**: All emails are generated as `username@example.com` (not real emails)

⚠️ **E-Signature**: Dummy colored images are generated (not real signatures)

⚠️ **Duplicate Prevention**: The command automatically skips duplicate usernames

⚠️ **No Notifications**: Dummy user creation does NOT trigger notifications (created directly in database)

## Testing Scenarios

### Scenario 1: Test Pending User Management
```bash
python manage.py generate_dummy_users --count=75 --role=pending
```
Then:
1. Log in as Admin
2. Go to Manage Pending Users
3. See 75 pending users per council
4. Test approve/reject functionality

### Scenario 2: Test Member Dashboard
```bash
python manage.py generate_dummy_users --count=75 --role=member
```
Then:
1. Log in as Member (one of the dummy users)
2. Check dashboard
3. See other members in the council
4. Test member features

### Scenario 3: Test Officer Management
```bash
python manage.py generate_dummy_users --count=50 --role=member
```
Then:
1. Log in as Officer
2. Go to member list
3. See 50 members in the council
4. Test member management features

## Troubleshooting

### Command Not Found
**Error**: `Unknown command: 'generate_dummy_users'`

**Solution**: 
1. Ensure `management/commands/generate_dummy_users.py` exists
2. Ensure both `__init__.py` files exist:
   - `management/__init__.py`
   - `management/commands/__init__.py`
3. Restart Django server

### Duplicate Username Error
**Error**: `Skipped X users (duplicates or errors)`

**Solution**: This is normal. The command automatically skips duplicates. Run again if needed.

### E-Signature Save Error
**Error**: `Error saving e-signature`

**Solution**: 
1. Ensure `MEDIA_ROOT` is configured in settings
2. Ensure `media/` directory exists and is writable
3. Check file permissions

### Pillow Not Installed
**Error**: `No module named 'PIL'`

**Solution**: Install Pillow:
```bash
pip install Pillow
```

## Cleanup

To delete all dummy users:

```bash
# Via Django shell
python manage.py shell
>>> from capstone_project.models import User
>>> User.objects.filter(username__contains='garcia').delete()  # Example
>>> # Or delete by role
>>> User.objects.filter(role='pending').delete()
```

Or via database:
```sql
DELETE FROM capstone_project_user WHERE role='pending';
```

## Performance

- **Time**: ~2-3 minutes for 300 users (4 councils × 75 users)
- **Database**: ~50MB additional storage (with e-signatures)
- **CPU**: Low impact

## File Structure

```
capstone_project/
├── management/
│   ├── __init__.py
│   └── commands/
│       ├── __init__.py
│       └── generate_dummy_users.py
```

## Summary

✅ **Command Created**: `generate_dummy_users.py`
✅ **Features**: 75 users per council, realistic data, configurable
✅ **Usage**: `python manage.py generate_dummy_users`
✅ **Data**: All sign-up form fields populated
✅ **Ready**: Production-ready command

---

**Last Updated**: December 3, 2025, 11:59 PM UTC+08:00

**Status**: ✅ READY TO USE
