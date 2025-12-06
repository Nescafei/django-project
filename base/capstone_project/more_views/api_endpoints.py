from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from capstone_project.models import Event, User, Council, EventAttendance
from django.db.models import Count, Q
import json
from datetime import date

@login_required
def user_counts_api(request):
    """API endpoint for admin dashboard user counts"""
    if request.user.role != 'admin':
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    # Get all members and officers (not archived)
    all_members = User.objects.filter(is_archived=False, role__in=['member', 'officer'])
    
    # Count active members (members/officers with activity in last 30 days)
    active_count = sum(1 for u in all_members if not u.is_inactive_member())
    
    # Count inactive members (members/officers with no activity in last 30 days)
    inactive_count = sum(1 for u in all_members if u.is_inactive_member())
    
    # Count pending users
    pending_count = User.objects.filter(role='pending', is_archived=False).count()
    
    # Total members (active + inactive, excluding pending and archived)
    total_members = active_count + inactive_count
    
    return JsonResponse({
        'active_count': active_count,
        'inactive_count': inactive_count,
        'pending_count': pending_count,
        'total_members': total_members
    })

@login_required
def council_user_counts_api(request):
    """API endpoint for officer dashboard council user counts"""
    if request.user.role not in ['admin', 'officer']:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    # Get user's council (for officers) or all councils (for admin)
    if request.user.role == 'officer':
        council = request.user.council
        if not council:
            return JsonResponse({'active_count': 0, 'inactive_count': 0, 'pending_count': 0, 'total_members': 0})
        
        # Get all members and officers in this council (not archived)
        council_members = User.objects.filter(is_archived=False, council=council, role__in=['member', 'officer'])
        
        # Count active members (with activity in last 30 days)
        active_count = sum(1 for u in council_members if not u.is_inactive_member())
        
        # Count inactive members (no activity in last 30 days)
        inactive_count = sum(1 for u in council_members if u.is_inactive_member())
        
        # Count pending users in this council
        pending_count = User.objects.filter(role='pending', council=council, is_archived=False).count()
        
        # Total members (active + inactive)
        total_members = active_count + inactive_count
    else:
        # Admin sees all council users
        all_members = User.objects.filter(is_archived=False, role__in=['member', 'officer'])
        
        # Count active members
        active_count = sum(1 for u in all_members if not u.is_inactive_member())
        
        # Count inactive members
        inactive_count = sum(1 for u in all_members if u.is_inactive_member())
        
        # Count pending users
        pending_count = User.objects.filter(role='pending', is_archived=False).count()
        
        # Total members
        total_members = active_count + inactive_count
    
    return JsonResponse({
        'active_count': active_count,
        'inactive_count': inactive_count,
        'pending_count': pending_count,
        'total_members': total_members
    })

@login_required
def event_counts_api(request):
    """API endpoint for event counts (admin sees all events)"""
    if request.user.role not in ['admin', 'officer']:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    pending_count = Event.objects.filter(status='pending').count()
    approved_count = Event.objects.filter(status='approved').count()
    
    # Check if there are new proposals (simplified - you can enhance this with timestamps)
    has_new_proposals = pending_count > 0
    
    return JsonResponse({
        'pending_count': pending_count,
        'approved_count': approved_count,
        'has_new_proposals': has_new_proposals
    })

@login_required
def council_event_counts_api(request):
    """API endpoint for council-specific event counts"""
    if request.user.role not in ['admin', 'officer']:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    # Get user's council (for officers) or all events (for admin)
    if request.user.role == 'officer':
        council = request.user.council
        if not council:
            return JsonResponse({'pending_count': 0, 'approved_count': 0})
        
        pending_count = Event.objects.filter(council=council, status='pending').count()
        approved_count = Event.objects.filter(council=council, status='approved').count()
    else:
        # Admin sees all events
        pending_count = Event.objects.filter(status='pending').count()
        approved_count = Event.objects.filter(status='approved').count()
    
    return JsonResponse({
        'pending_count': pending_count,
        'approved_count': approved_count
    })

@login_required
def event_download_data(request, event_id):
    """API endpoint to get event details with attendance count for download/print"""
    if request.user.role not in ['admin', 'officer']:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    try:
        event = Event.objects.get(id=event_id)
    except Event.DoesNotExist:
        return JsonResponse({'error': 'Event not found'}, status=404)
    
    # Check permissions - officers can only download their own council's events or global events
    if request.user.role == 'officer':
        if not event.is_global and event.council != request.user.council:
            return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    # Check if event is present or past
    today = date.today()
    if event.date_from > today:
        return JsonResponse({'error': 'Event has not started yet'}, status=400)
    
    # Get attendance count
    attendance_count = EventAttendance.objects.filter(event=event, is_present=True).count()
    total_attendees = EventAttendance.objects.filter(event=event).count()
    
    data = {
        'id': event.id,
        'name': event.name,
        'description': event.description,
        'category': event.category,
        'subcategory': event.subcategory or 'N/A',
        'date_from': event.date_from.strftime('%B %d, %Y'),
        'date_until': event.date_until.strftime('%B %d, %Y') if event.date_until else None,
        'council_name': event.council.name if event.council else "All Councils",
        'street': event.street,
        'barangay': event.barangay,
        'city': event.city,
        'province': event.province,
        'creator_name': f"{event.created_by.first_name} {event.created_by.last_name}" if event.created_by else "Unknown",
        'attendance_count': attendance_count,
        'total_attendees': total_attendees,
    }
    
    return JsonResponse(data)
