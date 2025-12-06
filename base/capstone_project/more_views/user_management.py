from ..models import User, Notification, EventAttendance, Recruitment, Council
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.db.models import Q
from django.contrib import messages
from ..notification_utils import (
    notify_user_promotion, notify_user_demotion, 
    notify_user_recruiter_assigned, notify_user_event_attended,
    notify_recruiter_manual_assignment, notify_recruit_manual_assignment
)

@never_cache
@login_required
def manage_pending_users(request):
    if request.user.role not in ['officer', 'admin']:
        return redirect('dashboard')
    if request.user.role == 'officer' and request.user.council:
        pending_users = User.objects.filter(role='pending', council=request.user.council, is_archived=False).exclude(role='admin')
    elif request.user.role == 'admin':
        pending_users = User.objects.filter(role='pending', is_archived=False).exclude(role='admin')
    else:
        pending_users = []
    return render(request, 'manage_pending_users.html', {'pending_users': pending_users})

@never_cache
@login_required
def approve_user(request, user_id):
    if request.user.role not in ['officer', 'admin']:
        return redirect('dashboard')
    
    user = get_object_or_404(User, id=user_id, is_archived=False)
    
    # Get the role from POST data (only admin can assign officer role)
    selected_role = request.POST.get('role', 'member')
    if selected_role == 'officer' and request.user.role != 'admin':
        selected_role = 'member'  # Officers can only approve as members
    
    if user.council == request.user.council or request.user.role == 'admin':
        user.role = selected_role
        # Ensure the user is active
        user.is_active = True
        
        # Set 1st degree for newly approved users
        if not user.current_degree:
            user.current_degree = '1st'
            print(f"User {user.username} assigned 1st degree upon approval")
        
        # Check if this user was recruited by someone
        if user.recruiter_name and not user.voluntary_join:
            try:
                from django.utils import timezone
                
                # Find the recruiter by name - improved matching logic
                recruiter_name = user.recruiter_name.strip()
                print(f"Looking for recruiter with name: {recruiter_name}")
                
                # Try exact match first (in case it's a username)
                recruiters = User.objects.filter(
                    username__iexact=recruiter_name,
                    is_archived=False
                )
                
                # If no match, try by first and last name
                if recruiters.count() == 0 and ' ' in recruiter_name:
                    recruiter_names = recruiter_name.split()
                    
                    # Try different combinations
                    if len(recruiter_names) >= 2:
                        first_name = recruiter_names[0]
                        last_name = recruiter_names[-1]
                        
                        # Try first and last name match
                        recruiters = User.objects.filter(
                            first_name__iexact=first_name,
                            last_name__iexact=last_name,
                            is_archived=False
                        )
                        
                        # If still no match, try partial matches
                        if recruiters.count() == 0:
                            recruiters = User.objects.filter(
                                first_name__icontains=first_name,
                                last_name__icontains=last_name,
                                is_archived=False
                            )
                
                # If we found exactly one recruiter, create the recruitment record
                if recruiters.count() == 1:
                    recruiter = recruiters.first()
                    print(f"Found recruiter: {recruiter.username} ({recruiter.first_name} {recruiter.last_name})")
                    
                    # Check if recruitment record already exists
                    existing_recruitment = Recruitment.objects.filter(
                        recruiter=recruiter,
                        recruited=user
                    ).first()
                    
                    if not existing_recruitment:
                        # Create recruitment record
                        Recruitment.objects.create(
                            recruiter=recruiter,
                            recruited=user,
                            date_recruited=timezone.now().date(),
                            is_manual=False  # This is automatically created, not manually added
                        )
                        print(f"Recruitment record created: {recruiter.username} recruited {user.username}")
                        
                        # Check if recruiter should be promoted to next degree
                        recalculate_degree(recruiter)
                    else:
                        print(f"Recruitment record already exists for {recruiter.username} and {user.username}")
                elif recruiters.count() > 1:
                    print(f"Multiple potential recruiters found for name '{recruiter_name}', skipping recruitment record")
                else:
                    print(f"No recruiter found for name '{recruiter_name}', skipping recruitment record")
            except Exception as e:
                print(f"Error processing recruiter information: {str(e)}")
                import traceback
                traceback.print_exc()
        
        user.save()
        messages.success(request, f'User {user.first_name} {user.last_name} has been approved as {selected_role}.')
        print(f"User {user.username} approved as {selected_role} by {request.user.username}")
    
    return redirect('manage_pending_users')

@never_cache
@login_required
def reject_user(request, user_id):
    if request.user.role not in ['officer', 'admin']:
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id, is_archived=False)
    if user.council == request.user.council or request.user.role == 'admin':
        user.is_active = False
        user.is_archived = True
        user.save()
        print(f"User {user.username} archived by {request.user.username}")
    return redirect('manage_pending_users')

@never_cache
@login_required
def promote_user(request, user_id):
    if request.user.role != 'admin':
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id, is_archived=False)
    user.role = 'officer'
    user.save()
    # Send notification to user
    notify_user_promotion(user, 'officer')
    messages.success(request, f"{user.first_name} {user.last_name} has been promoted to Officer.")
    return redirect('manage_roles')

@never_cache
@login_required
def demote_user(request, user_id):
    if request.user.role != 'admin':
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id, is_archived=False)
    old_role = user.role
    user.role = 'member'
    user.save()
    # Send notification to user
    notify_user_demotion(user, old_role)
    messages.success(request, f"{user.first_name} {user.last_name} has been demoted to Member.")
    return redirect('manage_roles')

@never_cache
@login_required
def archive_user(request, user_id):
    if request.user.role != 'admin':
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id, is_archived=False)
    if user == request.user:
        print(f"User {request.user.username} attempted to archive themselves")
        return redirect('dashboard')
    user.is_active = False
    user.is_archived = True
    user.save()
    print(f"User {user.username} archived by {request.user.username}")
    return redirect('dashboard')

@never_cache
@login_required
def archived_users(request):
    if request.user.role != 'admin':
        return redirect('dashboard')
    archived_users = User.objects.filter(is_archived=True)
    print(f"Admin {request.user.username} accessed archived users: {archived_users.count()} found")
    return render(request, 'archived_users.html', {'archived_users': archived_users})

@never_cache
@login_required
def update_degree(request, user_id):
    if request.user.role not in ['officer', 'admin']:
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id, is_archived=False)
    # Allow admin to modify any user, officer can only modify members in their council
    if request.user.role == 'officer' and (user.role != 'member' or user.council != request.user.council):
        return redirect('dashboard')
    if request.method == 'POST':
        degree = request.POST.get('current_degree')
        print(f"Received degree: {degree}")
        valid_degrees = [choice[0] for choice in User.DEGREE_CHOICES]
        print(f"Valid degrees: {valid_degrees}")
        if degree in valid_degrees:
            user.current_degree = degree
            user.save()
            print(f"User {user.username}'s degree updated to {degree} by {request.user.username}")
        else:
            print(f"Invalid degree {degree} selected for user {user.username}")
        return redirect('dashboard')
    return render(request, 'update_degree.html', {'user': user})

@never_cache
@login_required
def manage_roles(request):
    """View for admins to manage user roles (promote/demote)"""
    if request.user.role != 'admin':
        return redirect('dashboard')
        
    # Get all active users except admin
    users = User.objects.filter(is_archived=False).exclude(username='Mr_Admin')
    
    return render(request, 'manage_roles.html', {'users': users})

@login_required
def user_details(request, user_id):
    """API endpoint for user details"""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Not authorized'}, status=401)
        
    user = get_object_or_404(User, id=user_id)
    
    # If officer, they can only see details of users in their council
    if request.user.role == 'officer' and user.council != request.user.council:
        return JsonResponse({'error': 'Not authorized'}, status=403)
    
    data = {
        'id': user.id,
        'username': user.username,
        'first_name': user.first_name,
        'second_name': user.second_name,
        'last_name': user.last_name,
        'middle_name': user.middle_name,
        'middle_initial': user.middle_initial,
        'suffix': user.suffix,
        'email': user.email,
        'contact_number': user.contact_number,
        'birthday': user.birthday.strftime('%b %d, %Y') if user.birthday else None,
        'age': user.age,
        'street': user.street,
        'barangay': user.barangay,
        'city': user.city,
        'province': user.province,
        'zip_code': user.zip_code,
        'role': user.role,
        'role_display': user.get_role_display(),
        'council_name': user.council.name if user.council else None,
        'degree_display': user.get_current_degree_display(),
        'date_joined': user.date_joined.strftime('%b %d, %Y'),
        'marital_status': user.marital_status,
        'occupation': user.occupation,
        'recruiter_name': user.recruiter_name,
        'voluntary_join': user.voluntary_join,
        'join_reason': user.join_reason,
        'is_inactive': user.is_inactive_member(),
    }
    
    if user.profile_picture:
        data['profile_picture'] = user.profile_picture.url
        
    if user.e_signature:
        data['e_signature'] = user.e_signature.url
    
    return JsonResponse(data)

@never_cache
@login_required
def member_activities(request):
    """View for displaying a member's activities"""
    if request.user.role not in ['member', 'officer', 'admin']:
        return redirect('dashboard')
    
    # Get the member
    member_id = request.GET.get('member_id')
    if member_id and request.user.role in ['admin', 'officer']:
        # Admins and officers can view any member's activities
        member = get_object_or_404(User, id=member_id)
        # Officers can only view members in their council
        if request.user.role == 'officer' and member.council != request.user.council:
            messages.error(request, 'You can only view activities for members in your council.')
            return redirect('dashboard')
    else:
        # Members can only view their own activities
        member = request.user
    
    # Get the member's activities (events they attended)
    activities = EventAttendance.objects.filter(member=member, is_present=True).order_by('-event__date_from')
    
    context = {
        'member': member,
        'activities': activities,
        'is_self': member == request.user
    }
    
    return render(request, 'member_activities.html', context)

@never_cache
def search_members(request):
    """API endpoint for searching members for recruiter autocomplete"""
    query = request.GET.get('q', '')
    if not query or len(query) < 2:
        return JsonResponse({'members': []})
    
    # Search for active members (not pending or archived)
    members = User.objects.filter(
        Q(first_name__icontains=query) | 
        Q(last_name__icontains=query),
        is_archived=False,
        role__in=['member', 'officer', 'admin']
    ).select_related('council')[:10]  # Limit to 10 results
    
    results = [
        {
            'id': member.id,
            'first_name': member.first_name,
            'last_name': member.last_name,
            'full_name': f"{member.first_name} {member.last_name}",
            'council_name': member.council.name if member.council else None
        }
        for member in members
    ]
    
    return JsonResponse({'members': results})

def check_username(request):
    """API endpoint to check if a username already exists"""
    username = request.GET.get('username', '')
    if not username:
        return JsonResponse({'exists': False})
    
    exists = User.objects.filter(username=username, is_archived=False).exists()
    return JsonResponse({'exists': exists})

def check_email(request):
    """API endpoint to check if an email already exists"""
    email = request.GET.get('email', '')
    if not email:
        return JsonResponse({'exists': False})
    
    exists = User.objects.filter(email=email, is_archived=False).exists()
    return JsonResponse({'exists': exists})

def check_for_degree_promotion(user):
    """
    Check if a user should be promoted to the next degree based on recruitment criteria
    
    This is a wrapper around recalculate_degree for backward compatibility
    """
    return recalculate_degree(user)

def recalculate_degree(user):
    """
    Recalculate a user's degree based on their recruitment records
    
    Will promote or demote the user based on the current recruitment criteria:
    * 1st Degree: Default
    * 2nd Degree: 1-2 recruits (no longer than 1 month)
    * 3rd Degree: 3-4 recruits (even the past recruits/cumulative) attended recent events (no longer than 1 month)
    * 4th Degree: 5+ recruits (even the past recruits/cumulative) attended recent events (no longer than 1 month)
    """
    from django.utils import timezone
    from datetime import timedelta
    
    if not user or user.is_archived:
        print(f"Skipping degree recalculation for invalid or archived user")
        return False
    
    print(f"Recalculating degree for user {user.username} (current: {user.current_degree or '1st'})")
    
    # Get all recruitments by this user
    recruitments = Recruitment.objects.filter(recruiter=user)
    total_recruits = recruitments.count()
    
    # Get recent recruitments (within the last month)
    one_month_ago = timezone.now().date() - timedelta(days=30)
    recent_recruitments = recruitments.filter(date_recruited__gte=one_month_ago)
    recent_recruits_count = recent_recruitments.count()
    
    # Get recent event attendance
    recent_events_attended = EventAttendance.objects.filter(
        member=user,
        is_present=True,
        event__date_from__gte=one_month_ago
    ).count()
    
    print(f"User {user.username}: Total recruits: {total_recruits}, Recent recruits: {recent_recruits_count}, Recent events attended: {recent_events_attended}")
    
    # Store the original degree for comparison
    original_degree = user.current_degree or '1st'
    
    # Determine the appropriate degree based on criteria
    if total_recruits >= 5 and recent_events_attended > 0:
        new_degree = '4th'
    elif total_recruits >= 3 and recent_events_attended > 0:
        new_degree = '3rd'
    elif recent_recruits_count >= 1:
        new_degree = '2nd'
    else:
        new_degree = '1st'
    
    print(f"User {user.username}: Calculated appropriate degree: {new_degree}")
    
    # Degree rank mapping for proper comparison
    degree_rank = {
        '1st': 1,
        '2nd': 2,
        '3rd': 3,
        '4th': 4
    }
    
    # Update the user's degree if it has changed
    if new_degree != original_degree:
        user.current_degree = new_degree
        user.save()
        print(f"User {user.username}: Degree updated from {original_degree} to {new_degree}")
        
        # Create a notification for the user about their degree change
        try:
            if degree_rank[new_degree] > degree_rank[original_degree]:
                # Promotion
                Notification.objects.create(
                    user=user,
                    title=f"Congratulations! You've been promoted to {user.get_current_degree_display()}",
                    content=f"Your dedication to the Knights of Columbus has earned you a promotion to {user.get_current_degree_display()}.",
                    is_read=False
                )
                print(f"User {user.username}: Promotion notification created")
            else:
                # Demotion
                Notification.objects.create(
                    user=user,
                    title=f"Your degree has been updated to {user.get_current_degree_display()}",
                    content=f"Due to changes in your recruitment history, your degree has been updated to {user.get_current_degree_display()}.",
                    is_read=False
                )
                print(f"User {user.username}: Demotion notification created")
        except Exception as e:
            print(f"Error creating degree change notification: {str(e)}")
    
    return True

@never_cache
@login_required
def add_recruitment(request):
    """View for manually adding a recruitment record"""
    if request.user.role != 'admin':
        return redirect('dashboard')
        
    if request.method == 'POST':
        from django.utils import timezone
        
        recruiter_id = request.POST.get('recruiter_id')
        recruit_id = request.POST.get('recruit_id')
        
        try:
            recruiter = User.objects.get(id=recruiter_id, is_archived=False)
            recruit = User.objects.get(id=recruit_id, is_archived=False)
            
            # Check if the recruitment record already exists
            existing_recruitment = Recruitment.objects.filter(
                recruiter=recruiter,
                recruited=recruit
            ).first()
            
            if existing_recruitment:
                messages.warning(request, f'Recruitment record already exists for {recruiter.first_name} {recruiter.last_name} and {recruit.first_name} {recruit.last_name}.')
            else:
                # Create the recruitment record
                recruitment = Recruitment.objects.create(
                    recruiter=recruiter,
                    recruited=recruit,
                    date_recruited=timezone.now().date(),
                    is_manual=True,  # Mark as manually added
                    added_by=request.user  # Record who added it
                )
                
                # Notify both the recruiter and the recruit about the manual assignment
                notify_recruiter_manual_assignment(recruiter, recruit)
                notify_recruit_manual_assignment(recruit, recruiter)
                
                # Recalculate the recruiter's degree
                recalculate_degree(recruiter)
                
                messages.success(request, f'Recruitment record created: {recruiter.first_name} {recruiter.last_name} recruited {recruit.first_name} {recruit.last_name}.')
        except User.DoesNotExist:
            messages.error(request, 'One or both users not found.')
        except Exception as e:
            messages.error(request, f'Error creating recruitment record: {str(e)}')
    
    # Get all active members (not pending or archived)
    users = User.objects.filter(
        is_archived=False,
        role__in=['member', 'officer', 'admin']
    ).order_by('first_name', 'last_name')
    
    # Get all recruitment records
    all_recruitments = Recruitment.objects.all().select_related('recruiter', 'recruited').order_by('-date_recruited')
    
    return render(request, 'add_recruitment.html', {
        'users': users,
        'all_recruitments': all_recruitments
    })

@never_cache
@login_required
def undo_recruitment(request, history_id):
    """View for undoing a recruitment change"""
    if request.user.role != 'admin':
        return redirect('dashboard')
    
    recruitment = get_object_or_404(Recruitment, id=history_id)
    
    # Only allow undoing manual recruitments added by this admin
    if not recruitment.is_manual or recruitment.added_by != request.user:
        messages.error(request, "You can only undo recruitment records that you manually added.")
        return redirect('add_recruitment')
    
    if request.method == 'POST':
        try:
            recruiter = recruitment.recruiter
            recruiter_name = f"{recruiter.first_name} {recruiter.last_name}"
            recruit_name = f"{recruitment.recruited.first_name} {recruitment.recruited.last_name}"
            
            # Delete the recruitment record
            recruitment.delete()
            
            # Recalculate the recruiter's degree
            recalculate_degree(recruiter)
            
            messages.success(request, f'Recruitment record removed: {recruiter_name} recruiting {recruit_name}.')
        except Exception as e:
            messages.error(request, f'Error undoing recruitment record: {str(e)}')
    
    return redirect('add_recruitment')

@never_cache
@login_required
def change_council(request, user_id):
    """View for changing a member's council"""
    # Only admins and officers can change councils
    if request.user.role not in ['admin', 'officer']:
        messages.error(request, 'You do not have permission to change council assignments.')
        return redirect('dashboard')
    
    # Get the user
    user_to_change = get_object_or_404(User, id=user_id)
    
    # Admin can change council for any user
    # Officer can only change council for members in their council
    if request.user.role == 'officer':
        # Officers can only change members (not officers or admins)
        if user_to_change.role != 'member':
            messages.error(request, 'Officers can only change council for members, not for officers or admins.')
            return redirect('council_members')
            
        # Officers can only change members in their own council
        if user_to_change.council != request.user.council:
            messages.error(request, 'You can only change council for members in your council.')
            return redirect('council_members')
    
    # Get all councils
    councils = Council.objects.all()
    
    if request.method == 'POST':
        new_council_id = request.POST.get('council')
        
        try:
            new_council = Council.objects.get(id=new_council_id)
            old_council = user_to_change.council
            
            # Update the user's council
            user_to_change.council = new_council
            user_to_change.save()
            
            # Notify user of council transfer
            from ..notification_utils import notify_user_council_moved
            if old_council:
                notify_user_council_moved(user_to_change, new_council, old_council)
            
            messages.success(request, f'{user_to_change.first_name} {user_to_change.last_name} has been moved to {new_council.name}.')
            
            # Redirect based on user role
            if request.user.role == 'admin':
                return redirect('member_list')
            else:
                return redirect('council_members')
                
        except Council.DoesNotExist:
            messages.error(request, 'The selected council does not exist.')
    
    context = {
        'user_to_change': user_to_change,
        'councils': councils
    }
    
    return render(request, 'change_council.html', context)
