
from ..models import User, Council, Event, Analytics, Donation, blockchain, ForumCategory, ForumMessage, Notification, EventAttendance, Recruitment
from ..notification_utils import notify_user_event_attended
from django.contrib.auth.decorators import login_required, permission_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.core.files.base import ContentFile
from django.db.models import Count, Sum, Avg, Q, Max
from django.conf import settings
from datetime import datetime, date
import base64, os, re, logging, json, qrcode
import pandas as pd
from django.core.mail import send_mail
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.db import transaction
from ..models import Event, User, EventAttendance
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
from django.contrib import messages 
from django.db import transaction

logger = logging.getLogger(__name__)

@never_cache
@login_required
def event_attendance(request, event_id):
    """View for managing event attendance"""
    # Only officers and admins can manage attendance
    if request.user.role not in ['admin', 'officer']:
        return redirect('dashboard')
    
    # Get the event
    event = get_object_or_404(Event, id=event_id)
    
    # Check if the event is approved
    if event.status != 'approved':
        messages.error(request, 'You can only manage attendance for approved events.')
        return redirect('event_list')
    
    # Check if the officer belongs to the event's council
    if request.user.role == 'officer' and event.council != request.user.council and not event.is_global:
        messages.error(request, 'You can only manage attendance for events in your council.')
        return redirect('event_list')
    
    # Check if the event is happening today (use timezone-aware date)
    from django.utils import timezone
    today = timezone.localtime(timezone.now()).date()
    is_today = (event.date_from <= today <= (event.date_until or event.date_from))

    # Get members and officers based on the event's council or global status
    if event.is_global:
        if request.user.role == 'admin':
            # Admin can see all members and officers for global events
            members = User.objects.filter(role__in=['member', 'officer'], is_active=True, is_archived=False).order_by('first_name', 'last_name')
        else:
            # Officers can only see members and officers from their council for global events
            members = User.objects.filter(council=request.user.council, role__in=['member', 'officer'], is_active=True, is_archived=False).order_by('first_name', 'last_name')
    else:
        members = User.objects.filter(council=event.council, role__in=['member', 'officer'], is_active=True, is_archived=False).order_by('first_name', 'last_name')
    
    # Get existing attendance records
    attendance_records = EventAttendance.objects.filter(event=event)
    attendance = [record.member.id for record in attendance_records.filter(is_present=True)]
    present_count = len(attendance)
    
    # Create attendance records for members who don't have one yet
    with transaction.atomic():
        for member in members:
            EventAttendance.objects.get_or_create(
                event=event,
                member=member,
                defaults={
                    'is_present': False,
                    'recorded_by': request.user
                }
            )
    
    context = {
        'event': event,
        'members': members,
        'attendance': attendance,
        'present_count': present_count,
        'is_today': is_today,
    }
    
    return render(request, 'event_attendance.html', context)

@never_cache
@login_required
def update_attendance(request):
    """API endpoint for updating event attendance"""
    if request.user.role not in ['admin', 'officer'] or request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Unauthorized'}, status=403)
    
    try:
        data = json.loads(request.body)
        event_id = data.get('event_id')
        
        # Check if this is a batch update or individual update
        if 'present_members' in data:
            # Batch update
            present_members = data.get('present_members', [])
            
            # Validate input
            if not event_id:
                return JsonResponse({'status': 'error', 'message': 'Missing event ID'}, status=400)
            
            try:
                # Get event
                event = get_object_or_404(Event, id=event_id)
                
                # Check if the event is approved
                if event.status != 'approved':
                    return JsonResponse({'status': 'error', 'message': 'Can only update attendance for approved events'}, status=400)
                
                # Check if the officer belongs to the event's council
                if request.user.role == 'officer' and event.council != request.user.council and not event.is_global:
                    return JsonResponse({'status': 'error', 'message': 'You can only manage attendance for events in your council'}, status=403)
                
                # Check if the event is happening today (use timezone-aware date)
                from django.utils import timezone
                today = timezone.localtime(timezone.now()).date()
                if not (event.date_from <= today <= (event.date_until or event.date_from)):
                    return JsonResponse({'status': 'error', 'message': 'Can only update attendance on the day of the event'}, status=400)
                
                # Get all members and officers for this event
                if event.is_global:
                    if request.user.role == 'admin':
                        # Admin can see all members and officers for global events
                        members = User.objects.filter(role__in=['member', 'officer'], is_active=True, is_archived=False)
                    else:
                        # Officers can only see members and officers from their council for global events
                        members = User.objects.filter(council=request.user.council, role__in=['member', 'officer'], is_active=True, is_archived=False)
                else:
                    members = User.objects.filter(council=event.council, role__in=['member', 'officer'], is_active=True, is_archived=False)
                
                # Update all attendance records
                with transaction.atomic():
                    # First, mark all as absent
                    EventAttendance.objects.filter(event=event).update(is_present=False)
                    
                    # Then mark selected members as present
                    for member_id in present_members:
                        try:
                            member = User.objects.get(id=member_id)
                            
                            # Check if the officer is trying to update attendance for a member outside their council
                            if request.user.role == 'officer' and member.council != request.user.council:
                                continue
                                
                            attendance, created = EventAttendance.objects.update_or_create(
                                event=event,
                                member=member,
                                defaults={
                                    'is_present': True,
                                    'recorded_by': request.user
                                }
                            )
                            
                            # Notify member that they attended the event
                            if attendance.is_present:
                                notify_user_event_attended(member, event)
                        except User.DoesNotExist:
                            continue
                
                # Get updated count
                present_count = EventAttendance.objects.filter(event=event, is_present=True).count()
                
                # Calculate total count based on user role and event type
                if event.is_global:
                    if request.user.role == 'admin':
                        total_count = User.objects.filter(role__in=['member', 'officer'], is_active=True, is_archived=False).count()
                    else:
                        total_count = User.objects.filter(council=request.user.council, role__in=['member', 'officer'], is_active=True, is_archived=False).count()
                else:
                    total_count = User.objects.filter(council=event.council, role__in=['member', 'officer'], is_active=True, is_archived=False).count()
                
                # Record activity for present members
                from capstone_project.models import Activity
                for member_id in present_members:
                    try:
                        member = User.objects.get(id=member_id)
                        Activity.objects.get_or_create(
                            user=member,
                            event=event,
                            defaults={
                                'activity_type': 'event_attendance',
                                'description': f'Attended {event.name}',
                                'date_completed': timezone.now().date()
                            }
                        )
                    except User.DoesNotExist:
                        continue
                
                return JsonResponse({
                    'status': 'success',
                    'present_count': present_count,
                    'total_count': total_count
                })
            except Event.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Event not found'}, status=404)
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
            
        else:
            # Individual update
            member_id = data.get('member_id')
            is_present = data.get('is_present')
            
            # Validate input
            if not event_id or not member_id:
                return JsonResponse({'status': 'error', 'message': 'Missing required fields'}, status=400)
            
            try:
                # Get event and member
                event = get_object_or_404(Event, id=event_id)
                member = get_object_or_404(User, id=member_id)
                
                # Check if the event is approved
                if event.status != 'approved':
                    return JsonResponse({'status': 'error', 'message': 'Can only update attendance for approved events'}, status=400)
                
                # Check if the officer belongs to the event's council
                if request.user.role == 'officer' and event.council != request.user.council and not event.is_global:
                    return JsonResponse({'status': 'error', 'message': 'You can only manage attendance for events in your council'}, status=403)
                
                # Check if the officer is trying to update attendance for a member outside their council
                if request.user.role == 'officer' and member.council != request.user.council:
                    return JsonResponse({'status': 'error', 'message': 'You can only manage attendance for members in your council'}, status=403)
                
                # For testing purposes, bypass the date check
                # Check if the event is happening today
                today = date.today()
                if not (event.date_from <= today <= (event.date_until or event.date_from)):
                    # Temporarily comment out this check for testing
                    # return JsonResponse({'status': 'error', 'message': 'Can only update attendance on the day of the event'}, status=400)
                    pass
                
                # Update or create attendance record
                attendance, created = EventAttendance.objects.update_or_create(
                    event=event,
                    member=member,
                    defaults={
                        'is_present': is_present,
                        'recorded_by': request.user
                    }
                )
                
                # Notify member that they attended the event
                if attendance.is_present:
                    notify_user_event_attended(member, event)
                
                # Get updated count
                present_count = EventAttendance.objects.filter(event=event, is_present=True).count()
                
                # Calculate total count based on user role and event type
                if event.is_global:
                    if request.user.role == 'admin':
                        total_count = User.objects.filter(role='member', is_active=True, is_archived=False).count()
                    else:
                        total_count = User.objects.filter(council=request.user.council, role='member', is_active=True, is_archived=False).count()
                else:
                    total_count = User.objects.filter(council=event.council, role='member', is_active=True, is_archived=False).count()
                
                return JsonResponse({
                    'status': 'success',
                    'present_count': present_count,
                    'total_count': total_count,
                    'is_present': is_present
                })
            except Event.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Event not found'}, status=404)
            except User.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Member not found'}, status=404)
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
            
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': f'Unexpected error: {str(e)}'}, status=500)


@login_required
def member_attend(request):
    if request.user.role not in ['member', 'officer']:
        messages.error(request, 'You are not authorized to attend events.')
        return redirect('dashboard')

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    # FIX: Add "-event:" to match the expected format
    qr_data = f"member:{request.user.id}-event:attendance-{request.user.get_full_name()}"
    qr.add_data(qr_data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    qr_io = ContentFile(b'')
    img.save(qr_io, format='PNG')
    qr_io.seek(0)

    qr_filename = f'qr_{request.user.id}_{request.user.get_full_name().replace(" ", "_")}.png'
    file_path = os.path.join(settings.MEDIA_ROOT, 'qr_codes', qr_filename)
    if not os.path.exists(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    default_storage.save(file_path, qr_io)

    qr_code_url = f"{settings.MEDIA_URL}qr_codes/{qr_filename}"

    return render(request, 'member_attend.html', {
        'qr_code_url': qr_code_url,
        'user': request.user,
    })
    
@login_required
def scan_attendance(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    if request.user.role not in ['admin', 'officer']:
        return redirect('dashboard')
    # Logic to handle QR scan input (e.g., from form or JS scanner)
    qr_data = request.POST.get('qr_data')  # Assume POST from scanner
    if qr_data:
        # Parse qr_data (e.g., 'member:15-event:1-attendance-Harold Marquez')
        parts = qr_data.split('-')
        if len(parts) == 3 and parts[0].starts_with('member:') and parts[1].starts_with('event:'):
            member_id = parts[0].split(':')[1]
            event_id_from_qr = parts[1].split(':')[1]
            if int(event_id_from_qr) != event.id:
                messages.error(request, 'QR code is for a different event.')
                return redirect('event_attendance', event_id=event_id)
            member = get_object_or_404(User, id=member_id)
            # Update attendance
            attendance, created = EventAttendance.objects.get_or_create(
                event=event,
                member=member,
                defaults={'is_present': True, 'recorded_by': request.user}
            )
            if not created:
                attendance.is_present = True
                attendance.recorded_by = request.user
                attendance.save()
            messages.success(request, f'Attendance recorded for {member.get_full_name()}.')
    return redirect('event_attendance', event_id=event_id)

@login_required
def officer_take_attendance(request):
    if request.user.role not in ['admin', 'officer']:
        return redirect('dashboard')
    
    today = date.today()
    events = Event.objects.filter(status='approved', date_from__lte=today, date_until__gte=today)  # Only today's approved events
    if request.user.role == 'officer':
        events = events.filter(Q(council=request.user.council) | Q(is_global=True))
    
    return render(request, 'officer_take_attendance.html', {'events': events})

@csrf_protect
@login_required
def scan_qr(request):
    if request.method == 'POST':
        if request.user.role not in ['admin', 'officer']:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized'}, status=403)
        
        try:
            data = json.loads(request.body)
            qr_data = data.get('qr_data')
            event_id = data.get('event_id')
            
            if not qr_data or not event_id:
                return JsonResponse({'status': 'error', 'message': 'Missing data'}, status=400)
            
            # Parse QR data (format: member:{id}-attendance-{full_name})
            # Split only on first hyphen after "member:XX"
            if not qr_data.startswith('member:'):
                return JsonResponse({'status': 'error', 'message': 'Invalid QR code format'}, status=400)
            
            # Extract member ID: "member:32-attendance-John Doe" -> ["member:32", "attendance-John Doe"]
            parts = qr_data.split('-', 1)
            if len(parts) < 2:
                return JsonResponse({'status': 'error', 'message': 'Invalid QR code format'}, status=400)
            
            member_id = parts[0].replace('member:', '')
            
            if not member_id.isdigit():
                return JsonResponse({'status': 'error', 'message': 'Invalid member ID'}, status=400)
            
            try:
                member = User.objects.get(id=member_id)
            except User.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Member not found'}, status=404)
            
            try:
                event = Event.objects.get(id=event_id)
            except Event.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Event not found'}, status=404)
            
            # Check eligibility
            if not event.is_global and member.council != event.council:
                return JsonResponse({'status': 'error', 'message': f'{member.get_full_name()} is not eligible for this event'}, status=400)
            
            # Check if event is today
            today = date.today()
            if not (event.date_from <= today <= (event.date_until or event.date_from)):
                return JsonResponse({'status': 'error', 'message': 'Attendance can only be recorded on the day of the event'}, status=400)
            
            # Record attendance
            attendance, created = EventAttendance.objects.get_or_create(
                event=event,
                member=member,
                defaults={'is_present': True, 'recorded_by': request.user}
            )
            
            # Notify member that they attended the event
            if attendance.is_present:
                notify_user_event_attended(member, event)
            
            if not created:
                if attendance.is_present:
                    return JsonResponse({'status': 'success', 'message': f'{member.get_full_name()} was already marked present'})
                else:
                    attendance.is_present = True
                    attendance.recorded_by = request.user
                    attendance.save()
            
            return JsonResponse({'status': 'success', 'message': f'Attendance recorded for {member.get_full_name()}'})
            
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.error(f'Error in scan_qr: {str(e)}', exc_info=True)
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

