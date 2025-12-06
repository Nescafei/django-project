from ..models import  Council, Event
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.db.models import Q
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from ..models import Event
from django.contrib import messages
from ..notification_utils import (
    notify_admin_pending_proposal,
    notify_officer_proposal_status,
    notify_admin_event_today,
    notify_officer_event_today,
    notify_member_event_today
)
from datetime import date

@never_cache
@login_required
def add_event(request):
    if request.user.role not in ['admin', 'officer']:
        return redirect('dashboard')
        
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        category = request.POST.get('category')
        subcategory = request.POST.get('subcategory')
        street = request.POST.get('street')
        barangay = request.POST.get('barangay')
        city = request.POST.get('city')
        province = request.POST.get('province')
        date_from = request.POST.get('date_from')
        date_until = request.POST.get('date_until')
        is_global = request.POST.get('is_global') == 'on'  # Checkbox value
        enable_attendance = request.POST.get('enable_attendance') == 'on'  # New checkbox for attendance
        
        # Only admin can create global events
        if is_global and request.user.role != 'admin':
            is_global = False
            
        # Handle council selection
        if request.user.role == 'admin':
            if is_global:
                council = None
                status = 'approved'
            else:
                council_id = request.POST.get('council_id')
                try:
                    council = Council.objects.get(id=council_id)
                    status = 'approved'
                except Council.DoesNotExist:
                    messages.error(request, 'Invalid council selected.')
                    return redirect('add_event')
        else:
            council = request.user.council
            if not council:
                messages.error(request, 'You need to be assigned to a council to propose events.')
                return redirect('dashboard')
            status = 'pending'
            is_global = False  # Officers cannot propose global events
            
        try:
            event = Event.objects.create(
                name=name,
                description=description,
                category=category,
                subcategory=subcategory,
                council=council,
                is_global=is_global,
                street=street,
                barangay=barangay,
                city=city,
                province=province,
                date_from=date_from,
                date_until=date_until,
                status=status,
                created_by=request.user,
                enable_attendance=enable_attendance  # New field
            )
            
            if status == 'approved':
                event.approved_by = request.user
                event.save()
                messages.success(request, f'Event "{name}" has been created successfully.')
            else:
                # Notify admins of pending event proposal
                notify_admin_pending_proposal(request.user, proposal_type="event")
                messages.success(request, f'Event "{name}" has been proposed and is pending approval.')
                
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f'Error creating event: {str(e)}')
            
    councils = Council.objects.all() if request.user.role == 'admin' else None
    
    return render(request, 'add_event.html', {'councils': councils, 'is_admin': request.user.role == 'admin'})

@never_cache
@login_required
def edit_event(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    
    if request.user.role != 'admin' and request.user != event.created_by:
        messages.error(request, "You don't have permission to edit this event.")
        return redirect('dashboard')
        
    if request.method == 'POST':
        event.name = request.POST.get('name')
        event.description = request.POST.get('description')
        event.category = request.POST.get('category')
        event.subcategory = request.POST.get('subcategory')
        event.street = request.POST.get('street')
        event.barangay = request.POST.get('barangay')
        event.city = request.POST.get('city')
        event.province = request.POST.get('province')
        event.date_from = request.POST.get('date_from')
        event.date_until = request.POST.get('date_until')
        event.enable_attendance = request.POST.get('enable_attendance') == 'on'  # New field
        
        if request.user.role == 'admin':
            is_global = request.POST.get('is_global') == 'on'
            event.is_global = is_global
            
            if is_global:
                event.council = None
            elif request.POST.get('council_id'):
                try:
                    council = Council.objects.get(id=request.POST.get('council_id'))
                    event.council = council
                except Council.DoesNotExist:
                    messages.error(request, 'Invalid council selected.')
                    return redirect('edit_event', event_id=event_id)
        
        try:
            event.save()
            messages.success(request, f'Event "{event.name}" has been updated successfully.')
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f'Error updating event: {str(e)}')
    
    councils = Council.objects.all() if request.user.role == 'admin' else None
    
    return render(request, 'edit_event.html', {
        'event': event,
        'councils': councils,
        'is_admin': request.user.role == 'admin'
    })

@never_cache
@login_required
def event_proposals(request):
    """View for admins to manage event proposals"""
    if request.user.role != 'admin':
        return redirect('dashboard')
        
    # Get pending events
    pending_events = Event.objects.filter(status='pending')
    
    # Get previously processed events (approved or rejected)
    previous_events = Event.objects.filter(
        Q(status='approved') | Q(status='rejected')
    ).order_by('-updated_at')[:20]  # Limit to 20 most recent
    
    return render(request, 'event_proposals.html', {
        'pending_events': pending_events,
        'previous_events': previous_events
    })

@never_cache
@login_required
def approve_event(request, event_id):
    """Approve an event proposal"""
    if request.user.role != 'admin':
        return redirect('dashboard')
        
    event = get_object_or_404(Event, id=event_id)
    
    if event.status == 'pending':
        event.status = 'approved'
        event.approved_by = request.user
        event.save()
        
        # Notify the officer who proposed the event
        notify_officer_proposal_status(event.created_by, event, status='approved')
        
        # If event is happening today, notify all users
        if event.date_from == date.today():
            notify_admin_event_today(event)
            if event.council:
                notify_officer_event_today(event)
                notify_member_event_today(event)
        
        messages.success(request, f'Event "{event.name}" has been approved.')
        
    return redirect('event_proposals')

@never_cache
@login_required
def reject_event(request, event_id):
    """Reject an event proposal"""
    if request.user.role != 'admin':
        return redirect('dashboard')
        
    event = get_object_or_404(Event, id=event_id)
    
    if event.status == 'pending':
        if request.method == 'POST':
            rejection_category = request.POST.get('rejection_category', '')
            custom_reason = request.POST.get('custom_reason', '')
            additional_notes = request.POST.get('additional_notes', '')
            
            # Build the final rejection reason
            if rejection_category == 'Others':
                final_reason = f"Others: {custom_reason}"
            else:
                final_reason = rejection_category
            
            # Add additional notes if provided
            if additional_notes:
                final_reason += f"\n\nAdditional Notes: {additional_notes}"
            
            event.status = 'rejected'
            event.rejection_reason = final_reason
            event.save()
            
            # Notify the officer who proposed the event
            notify_officer_proposal_status(event.created_by, event, status='rejected')
            
            messages.success(request, f'Event "{event.name}" has been rejected.')
            return redirect('event_proposals')
        else:
            # Show rejection form
            return render(request, 'reject_event.html', {'event': event})
    else:
        messages.error(request, 'Only pending events can be rejected.')
    
    return redirect('event_proposals')

@never_cache
def event_details(request, event_id):
    """API endpoint for event details - allows unauthenticated users to view approved events"""
    event = get_object_or_404(Event, id=event_id)
    
    # Unauthenticated users can only see approved events
    if not request.user.is_authenticated:
        if event.status != 'approved':
            return JsonResponse({'error': 'Not authorized'}, status=403)
    # If authenticated but not admin, users can only see their council's events, global events, or approved events
    elif request.user.role != 'admin':
        if not event.is_global and event.council != request.user.council and event.status != 'approved':
            return JsonResponse({'error': 'Not authorized'}, status=403)
    
    data = {
        'id': event.id,
        'name': event.name,
        'description': event.description,
        'category': event.category,
        'date_from': event.date_from.strftime('%b %d, %Y'),
        'council_name': event.council.name if event.council else "All Councils",
        'is_global': event.is_global,
        'street': event.street,
        'barangay': event.barangay,
        'city': event.city,
        'province': event.province,
        'status': event.status,
        'status_display': event.get_status_display(),
        'creator_name': f"{event.created_by.first_name} {event.created_by.last_name}" if event.created_by else "Unknown"
    }
    
    if event.date_until and event.date_until != event.date_from:
        data['date_until'] = event.date_until.strftime('%b %d, %Y')
    
    if event.status == 'rejected' and event.rejection_reason:
        data['rejection_reason'] = event.rejection_reason
    
    return JsonResponse(data)

@never_cache
@login_required
def archived_events(request):
    """View for displaying archived (past) events with filtering options"""
    from datetime import date
    today = date.today()
    
    user = request.user
    if not user.is_authenticated or user.role == 'pending':
        return redirect('sign-in')
        
    # Get past events based on user role (events that have ended)
    past_events_query = Q(date_from__lt=today) & Q(Q(date_until__lt=today) | Q(date_until__isnull=True))
    
    # Include rejected events regardless of date
    rejected_events_query = Q(status='rejected')
    
    # Combined query for past events or rejected events
    combined_query = past_events_query | rejected_events_query
    
    if user.role == 'admin':
        # Admin sees all past events and all rejected events
        past_events = Event.objects.filter(combined_query)
        
    elif user.role in ['officer', 'member']:
        # Officers and members see their council's past events, global events, and rejected events
        past_events = Event.objects.filter(
            combined_query & (Q(council=user.council) | Q(is_global=True))
        )
    else:
        return redirect('dashboard')
        
    # Sort events based on user preference
    sort_by = request.GET.get('sort', 'date_desc')
    if sort_by == 'name':
        past_events = past_events.order_by('name')
    elif sort_by == 'date':
        past_events = past_events.order_by('date_from')
    elif sort_by == 'category':
        past_events = past_events.order_by('category', '-date_from')
    else:  # Default: date descending (most recent first)
        past_events = past_events.order_by('-date_from')
    
    # Filter by category if specified
    category_filter = request.GET.get('category', None)
    if category_filter and category_filter != 'all':
        past_events = past_events.filter(category=category_filter)
    
    # Filter by status if specified
    status_filter = request.GET.get('status', None)
    if status_filter and status_filter != 'all':
        past_events = past_events.filter(status=status_filter)
    
    # Filter by council if specified (for admin users)
    council_filter = request.GET.get('council', None)
    if council_filter and council_filter != 'all' and user.role == 'admin':
        past_events = past_events.filter(council_id=council_filter)
        
    context = {
        'past_events': past_events,
        'user': user,
        'sort_by': sort_by,
        'category_filter': category_filter,
        'status_filter': status_filter,
        'council_filter': council_filter,
        'councils': Council.objects.all() if user.role == 'admin' else None,
    }
    
    return render(request, 'archived_events.html', context)

@never_cache
@login_required
def event_list(request):
    """View for displaying a list of all events with filtering options"""
    from datetime import date
    today = date.today()
    
    # Only show current and future events, past events should be in archived_events
    base_query = Q(date_from__gte=today) | Q(date_until__gte=today)
    
    # Get status filter first
    status_filter = request.GET.get('status', None)
    
    # Filter events based on user role
    if request.user.role == 'member':
        # Members can only see approved events from their own council or global events
        events = Event.objects.filter(
            base_query & 
            Q(status='approved') & 
            (Q(council=request.user.council) | Q(is_global=True))
        )
    elif request.user.role == 'officer':
        # Officers can see events from their own council or global events
        # They can see all statuses for their own events, but only approved for others
        if status_filter and status_filter != 'all':
            if status_filter == 'approved':
                events = Event.objects.filter(
                    base_query & 
                    Q(status='approved') & 
                    (Q(council=request.user.council) | Q(is_global=True))
                )
            else:
                # For pending/rejected, only show their own events
                events = Event.objects.filter(
                    base_query & 
                    Q(status=status_filter) & 
                    Q(created_by=request.user) &
                    (Q(council=request.user.council) | Q(is_global=True))
                )
        else:
            # Default: show approved events from their council + their own events of any status
            events = Event.objects.filter(
                base_query & 
                (
                    (Q(status='approved') & (Q(council=request.user.council) | Q(is_global=True))) |
                    Q(created_by=request.user)
                )
            )
    else:
        # Admins see all events from all councils
        events = Event.objects.filter(base_query)
        
        # Apply status filter for admins
        if status_filter and status_filter != 'all':
            events = events.filter(status=status_filter)
    
    # Filter by category if specified
    category_filter = request.GET.get('category', None)
    if category_filter and category_filter != 'all':
        events = events.filter(category=category_filter)
    
    # Filter by council if specified (for admin users)
    council_filter = request.GET.get('council', None)
    if council_filter and council_filter != 'all' and request.user.role == 'admin':
        events = events.filter(council_id=council_filter)
    
    # Sort events based on user preference
    sort_by = request.GET.get('sort', 'date')
    if sort_by == 'name':
        events = events.order_by('name')
    elif sort_by == 'date_desc':
        events = events.order_by('-date_from')
    elif sort_by == 'category':
        events = events.order_by('category', 'date_from')
    else:  # Default: date ascending (soonest first)
        events = events.order_by('date_from')
    
    # Get all councils for filter dropdown (admin only)
    councils = None
    if request.user.role == 'admin':
        councils = Council.objects.all()
    
    # Check if events are happening today (for officers to manage attendance)
    for event in events:
        event.is_today = (event.date_from <= today <= (event.date_until or event.date_from))
    
    context = {
        'events': events,
        'councils': councils,
        'status_filter': status_filter,
        'category_filter': category_filter,
        'council_filter': council_filter,
        'sort_by': sort_by,
    }
    
    return render(request, 'event_list.html', context)

@never_cache
def approved_events(request):
    """View for displaying approved events to all users (authenticated and non-authenticated)"""
    from datetime import date
    today = date.today()
    
    # Show only approved events that are current or future
    base_query = Q(date_from__gte=today) | Q(date_until__gte=today)
    
    # All users (authenticated or not) can see ALL approved events regardless of council
    events = Event.objects.filter(base_query & Q(status='approved')).order_by('date_from')
    
    # Filter by category if specified
    category_filter = request.GET.get('category', None)
    if category_filter and category_filter != 'all':
        events = events.filter(category=category_filter)
    
    # Filter by council if specified
    council_filter = request.GET.get('council', None)
    if council_filter and council_filter != 'all':
        events = events.filter(council_id=council_filter)
    
    # Filter by province if specified
    province_filter = request.GET.get('province', None)
    if province_filter and province_filter != 'all':
        events = events.filter(province=province_filter)
    
    # Filter by city if specified
    city_filter = request.GET.get('city', None)
    if city_filter and city_filter != 'all':
        events = events.filter(city=city_filter)
    
    # Filter by barangay if specified
    barangay_filter = request.GET.get('barangay', None)
    if barangay_filter and barangay_filter != 'all':
        events = events.filter(barangay=barangay_filter)
    
    # Search functionality
    search_query = request.GET.get('search', None)
    if search_query:
        events = events.filter(
            Q(name__icontains=search_query) | 
            Q(description__icontains=search_query) |
            Q(category__icontains=search_query)
        )
    
    # Sort events
    sort_by = request.GET.get('sort', 'date')
    if sort_by == 'name':
        events = events.order_by('name')
    elif sort_by == 'date_desc':
        events = events.order_by('-date_from')
    elif sort_by == 'category':
        events = events.order_by('category', 'date_from')
    else:  # Default: date ascending (soonest first)
        events = events.order_by('date_from')
    
    # Get all councils for filter dropdown
    councils = Council.objects.all()
    
    # Get unique categories for filter
    categories = Event.objects.filter(status='approved').values_list('category', flat=True).distinct()
    
    # Get unique provinces for filter
    provinces = Event.objects.filter(status='approved').values_list('province', flat=True).distinct().order_by('province')
    
    context = {
        'events': events,
        'councils': councils,
        'categories': categories,
        'provinces': provinces,
        'category_filter': category_filter,
        'council_filter': council_filter,
        'province_filter': province_filter,
        'city_filter': city_filter,
        'barangay_filter': barangay_filter,
        'search_query': search_query,
        'sort_by': sort_by,
    }
    
    return render(request, 'approved_events.html', context)
