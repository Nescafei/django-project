from ..models import User, Council, Event, Analytics, Donation, blockchain, ForumCategory, ForumMessage, Notification, EventAttendance, Recruitment
from django.contrib.auth.decorators import login_required, permission_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.core.files.base import ContentFile
from django.db.models import Count, Q
from django.conf import settings
from datetime import datetime
import base64, re, logging
from django.core.mail import send_mail
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from ..models import Event, User, EventAttendance
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
from django.contrib import messages 

logger = logging.getLogger(__name__)

def about_us(request):
    return render(request, 'about_us.html')

def events_management(request):
    return render(request, 'events_management.html')

def donation_reports(request):
    return render(request, 'donation_reports.html')

def mission_vision(request):
    return render(request, 'mission_vision.html')

def faith_action(request):
    return render(request, 'faith-action.html')

def councils(request):
    councils = Council.objects.all()
    return render(request, 'councils.html', {'councils': councils})

def council_detail(request, council_id):
    try:
        council = Council.objects.get(id=council_id)
        
        # Get admin, officers, and members for this council
        admin = User.objects.filter(council=council, role='admin', is_archived=False).first()
        officers = User.objects.filter(council=council, role='officer', is_archived=False).order_by('first_name')
        members = User.objects.filter(council=council, role='member', is_archived=False).order_by('first_name')
        
        context = {
            'council': council,
            'admin': admin,
            'officers': officers,
            'members': members
        }
        
        return render(request, 'council_detail.html', context)
    except Council.DoesNotExist:
        # Handle case where council doesn't exist
        return redirect('councils')

@never_cache
def sign_in(request):
    if request.user.is_authenticated:
        print(f"User {request.user.username} already authenticated, redirecting to dashboard")
        return redirect('dashboard')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        print(f"Attempting to authenticate user: {username}")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            if user.is_active and not user.is_archived:
                if user.role == 'pending':
                    messages.warning(request, 'Your account is pending approval. Please wait for an officer to review your request.')
                    print(f"User {username} is pending approval")
                    return render(request, 'sign-in.html')
                else:
                    login(request, user)
                    # Set session to expire according to settings (8 hours)
                    request.session.set_expiry(settings.SESSION_COOKIE_AGE)
                    # Initialize last_activity timestamp
                    request.session['last_activity'] = datetime.now().timestamp()
                    request.session.modified = True
                    
                    # Check if user is inactive and show warning (only once per session)
                    if user.is_inactive_member() and not request.session.get('inactive_warning_shown', False):
                        request.session['inactive_warning_shown'] = True
                        request.session['show_inactive_warning'] = True
                        request.session.modified = True
                    
                    print(f"User {username} logged in successfully, role: {user.role}, redirecting to dashboard")
                    return redirect('dashboard')
            else:
                print(f"User {username} is not active or is archived")
                messages.error(request, 'This account is not active or has been archived')
                return render(request, 'sign-in.html')
        else:
            print(f"Authentication failed for username: {username}")
            messages.error(request, 'Invalid username or password')
            return render(request, 'sign-in.html')
    print("Rendering sign-in page")
    return render(request, 'sign-in.html')

@never_cache
def sign_up(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    councils = Council.objects.all()
    print(f"Number of councils available: {councils.count()}")
    if request.method == 'POST':
        from ..notification_utils import notify_admin_pending_proposal, notify_officer_pending_member
        # Debug information for file uploads
        print(f"POST data: {request.POST}")
        print(f"FILES data: {request.FILES}")
        if 'e_signature' in request.FILES:
            e_signature_file = request.FILES['e_signature']
            print(f"E-signature file received: {e_signature_file.name}, size: {e_signature_file.size}, type: {e_signature_file.content_type}")
        else:
            print("No e-signature file received in request.FILES")
            
        first_name = request.POST.get('first_name')
        second_name = request.POST.get('second_name', '')  # Optional
        middle_name = request.POST.get('middle_name')
        last_name = request.POST.get('last_name')
        suffix = request.POST.get('suffix', '')  # Optional
        username = request.POST.get('username')
        email = request.POST.get('email', '')
        password = request.POST.get('password')
        re_password = request.POST.get('re_password')
        birthday = request.POST.get('birthday')
        street = request.POST.get('street')
        barangay = request.POST.get('barangay')
        city = request.POST.get('city')
        province = request.POST.get('province')
        zip_code = request.POST.get('zip_code')
        contact_number = request.POST.get('contact_number')
        council_id = request.POST.get('council', '')
        # New fields
        practical_catholic = request.POST.get('practical_catholic')
        marital_status = request.POST.get('marital_status')
        occupation = request.POST.get('occupation')
        recruiter_name = request.POST.get('recruiter_name', '')
        voluntary_join = request.POST.get('voluntary_join') == 'on'
        privacy_agreement = request.POST.get('privacy_agreement')
        e_signature = request.FILES.get('e_signature')
        join_reason = request.POST.get('join_reason', '')
        
        # Set default values for gender and religion
        gender = 'Male'  # Default to Male for Knights of Columbus
        religion = 'Catholic'  # Default to Catholic for Knights of Columbus
        
        print(f"Received form data: first_name={first_name}, second_name={second_name}, middle_name={middle_name}, last_name={last_name}, suffix={suffix}, username={username}, email={email}, council_id={council_id}, birthday={birthday}, street={street}, barangay={barangay}, city={city}, province={province}, contact_number={contact_number}, practical_catholic={practical_catholic}, marital_status={marital_status}, occupation={occupation}, recruiter_name={recruiter_name}, voluntary_join={voluntary_join}, privacy_agreement={privacy_agreement}, e_signature={e_signature.name if e_signature else None}, join_reason={join_reason}")

        if password != re_password:
            print("Validation failed: Passwords do not match")
            messages.error(request, 'Passwords do not match')
            return render(request, 'sign-up.html', {'councils': councils})

        if not username:
            print("Validation failed: Username is required")
            messages.error(request, 'Username is required')
            return render(request, 'sign-up.html', {'councils': councils})

        if User.objects.filter(username=username, is_archived=False).exists():
            print(f"Validation failed: Username {username} already exists")
            messages.error(request, 'This username is already taken')
            return render(request, 'sign-up.html', {'councils': councils})

        # Check if email already exists
        if email and User.objects.filter(email=email, is_archived=False).exists():
            print(f"Validation failed: Email {email} already exists")
            messages.error(request, 'This email address is already registered')
            return render(request, 'sign-up.html', {'councils': councils})

        # Calculate age from birthday
        birth_date = None
        age = None
        if birthday:
            try:
                birth_date = datetime.strptime(birthday, '%Y-%m-%d').date()
                today = datetime.today().date()
                age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
                if age < 18:
                    print("Validation failed: User must be at least 18 years old")
                    messages.error(request, 'You must be at least 18 years old to sign up')
                    return render(request, 'sign-up.html', {'councils': councils})
            except ValueError as e:
                print(f"Validation failed: Invalid birthday format - {str(e)}")
                messages.error(request, 'Invalid birthday format. Use YYYY-MM-DD.')
                return render(request, 'sign-up.html', {'councils': councils})
        else:
            print("Validation failed: Birthday is required")
            messages.error(request, 'Birthday is required')
            return render(request, 'sign-up.html', {'councils': councils})

        # Validate practical Catholic
        if practical_catholic != 'Yes':
            print("Validation failed: User must be a practical Catholic")
            messages.error(request, 'You must be a practical Catholic to join Knights of Columbus')
            return render(request, 'sign-up.html', {'councils': councils})

        # Validate privacy agreement
        if privacy_agreement != 'agree':
            print("Validation failed: User must agree to the privacy policy")
            messages.error(request, 'You must agree to the data privacy agreement to create an account')
            return render(request, 'sign-up.html', {'councils': councils})

        # Validate e-signature
        if not e_signature:
            print("Validation failed: E-signature is required")
            messages.error(request, 'Please upload your e-signature')
            return render(request, 'sign-up.html', {'councils': councils})
        
        # Check e-signature file size (5MB limit)
        if e_signature.size > 5 * 1024 * 1024:  # 5MB in bytes
            print(f"Validation failed: E-signature file size exceeds 5MB limit. Size: {e_signature.size} bytes")
            messages.error(request, 'E-signature file size exceeds 5MB limit')
            return render(request, 'sign-up.html', {'councils': councils})
        
        # Check e-signature file type
        allowed_types = ['image/jpeg', 'image/png', 'image/gif']
        if hasattr(e_signature, 'content_type') and e_signature.content_type not in allowed_types:
            print(f"Validation failed: Invalid e-signature file type: {e_signature.content_type}")
            messages.error(request, f'E-signature must be a JPG, PNG, or GIF image. Detected: {e_signature.content_type}')
            return render(request, 'sign-up.html', {'councils': councils})

        try:
            council = Council.objects.get(id=council_id) if council_id else None
            if not council and council_id:
                print("Validation failed: Invalid council selected")
                messages.error(request, 'Invalid council selected')
                return render(request, 'sign-up.html', {'councils': councils})
        except Council.DoesNotExist:
            print("Validation failed: Council does not exist")
            messages.error(request, 'Invalid council selected')
            return render(request, 'sign-up.html', {'councils': councils})

        # Generate middle initial from middle name
        middle_initial = f"{middle_name[0]}." if middle_name else None

        try:
            # Create user without saving e-signature first
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                role='pending',
                council=council,
                age=age,
                first_name=first_name,
                second_name=second_name,
                middle_name=middle_name,
                middle_initial=middle_initial,
                last_name=last_name,
                suffix=suffix,
                street=street,
                barangay=barangay,
                city=city,
                province=province,
                zip_code=zip_code,
                contact_number=contact_number,
                birthday=birth_date,
                gender=gender,
                religion=religion,
                # Save new fields
                practical_catholic=practical_catholic == 'Yes',
                marital_status=marital_status,
                occupation=occupation,
                recruiter_name='' if voluntary_join else recruiter_name,
                voluntary_join=voluntary_join,
                join_reason=join_reason
            )
            
            # Save e-signature in a separate step
            if e_signature:
                try:
                    user.e_signature = e_signature
                    user.save()
                    print(f"E-signature saved successfully for user {username}")
                except Exception as e:
                    print(f"Error saving e-signature: {str(e)}")
                    # Continue with registration even if e-signature fails
            
            print(f"User {username} saved successfully with details: email={email}, role={user.role}, council={council}, age={age}, birthday={user.birthday}, first_name={first_name}, second_name={second_name}, middle_name={middle_name}, middle_initial={middle_initial}, last_name={last_name}, suffix={suffix}, street={street}, barangay={barangay}, city={city}, province={province}, zip_code={zip_code}, contact_number={contact_number}, gender={gender}, religion={religion}, practical_catholic={practical_catholic}, marital_status={marital_status}, occupation={occupation}, recruiter_name={recruiter_name}, voluntary_join={voluntary_join}, join_reason={join_reason}")
            
            # Send notifications
            # Notify admin of pending user
            notify_admin_pending_proposal(user, proposal_type="member")
            
            # Notify officer of pending user in their council
            if council:
                officers = User.objects.filter(council=council, role='officer', is_active=True)
                for officer in officers:
                    notify_officer_pending_member(officer, user)
            
            messages.success(request, 'Account request submitted. Awaiting approval. Use your username to sign in once approved.')
            return render(request, 'sign-up.html', {'councils': councils})
        except Exception as e:
            print(f"Error creating user: {str(e)}")
            messages.error(request, f'An error occurred during registration: {str(e)}')
            return render(request, 'sign-up.html', {'councils': councils})
    return render(request, 'sign-up.html', {'councils': councils})

def logout_view(request):
    logout(request)
    print("User logged out")
    response = redirect('sign-in')
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

@never_cache
@login_required
def dashboard(request):
    from datetime import date
    today = date.today()
    
    # Session refresh - update the session expiry time on each request
    request.session.set_expiry(settings.SESSION_COOKIE_AGE)
    request.session.modified = True
    
    user = request.user
    if user.role == 'pending':
        print(f"User {user.username} is pending, redirecting to sign-in")
        return render(request, 'sign-in.html', {'pending_message': 'Your account is pending approval. Please wait for an officer to review your request.'})
    
    if user.role == 'admin':
        return admin_dashboard(request)
    elif user.role == 'officer':
        return officer_dashboard(request)
    elif user.role == 'member':
        return member_dashboard(request)
    else:
        logout(request)
        return redirect('sign-in')

def admin_dashboard(request):
    """Dashboard view for admins"""
    from datetime import date
    from ..bible_verses import get_daily_bible_verse
    today = date.today()
    
    user = request.user
    user_list = User.objects.filter(is_archived=False)
    
    # Only show approved upcoming events (not pending or rejected)
    events = Event.objects.filter(
        date_from__gte=today,
        status='approved'
    )
    
    # Count only approved events
    approved_events_count = Event.objects.filter(status='approved', date_from__gte=today).count()
    
    # Count pending events for admin dashboard
    pending_events_count = Event.objects.filter(status='pending', date_from__gte=today).count()
    
    analytics = Analytics.objects.all()
    
    # Calculate user's recruitment count
    user_recruitment_count = user.recruitments.count()
    
    # Count pending users for admin dashboard
    pending_users_count = User.objects.filter(role='pending', is_archived=False).count()
    
    # Get all members and officers (not archived)
    all_members = User.objects.filter(is_archived=False, role__in=['member', 'officer'])
    
    # Count active users (members/officers with activity in last 30 days)
    active_users_count = sum(1 for u in all_members if not u.is_inactive_member())
    
    # Count inactive users (members/officers with no activity in 30 days)
    inactive_users_count = sum(1 for u in all_members if u.is_inactive_member())
    
    # Total members (active + inactive)
    total_members = active_users_count + inactive_users_count
    
    # Get daily Bible verse
    daily_verse = get_daily_bible_verse()
    
    # Check if we need to show inactive warning popup
    show_inactive_warning = request.session.pop('show_inactive_warning', False)
    
    # Count total councils
    councils_count = Council.objects.count()
    
    context = {
        'user': user,
        'user_list': user_list, 
        'events': events, 
        'approved_events_count': approved_events_count,
        'pending_events_count': pending_events_count,
        'analytics': analytics,
        'user_recruitment_count': user_recruitment_count,
        'pending_users_count': pending_users_count,
        'active_users_count': active_users_count,
        'inactive_users_count': inactive_users_count,
        'total_members': total_members,
        'daily_verse': daily_verse,
        'show_inactive_warning': show_inactive_warning,
        'councils_count': councils_count
    }
    
    return render(request, 'admin_dashboard.html', context)

def officer_dashboard(request):
    """Dashboard view for officers"""
    from datetime import date
    from ..bible_verses import get_daily_bible_verse
    today = date.today()
    
    user = request.user
    if not user.council:
        return redirect('dashboard')  # Redirect if no council assigned
    
    user_list = User.objects.filter(council=user.council, is_archived=False)
    
    # Officers see their council's current/future events and global events
    # Only show approved and pending events (not rejected)
    events = Event.objects.filter(
        (Q(council=user.council) | Q(is_global=True)) & 
        Q(date_from__gte=today)
    )
    # Count only approved events
    approved_events_count = Event.objects.filter(
        (Q(council=user.council) | Q(is_global=True)) & 
        Q(status='approved', date_from__gte=today)
    ).count()
    
    # Count pending events for officers
    pending_events_count = Event.objects.filter(
        (Q(council=user.council) | Q(is_global=True)) & 
        Q(status='pending', date_from__gte=today)
    ).count()
    
    analytics = Analytics.objects.filter(council=user.council)
    
    # Get activities (events attended) for officers too
    activities_count = EventAttendance.objects.filter(member=user, is_present=True).count()
    
    # Calculate user's recruitment count
    user_recruitment_count = user.recruitments.count()
    
    # Count pending users for officer dashboard (only their council)
    pending_users_count = User.objects.filter(role='pending', council=user.council, is_archived=False).count()
    
    # Get all members and officers in officer's council (not archived)
    council_members = User.objects.filter(is_archived=False, council=user.council, role__in=['member', 'officer'])
    
    # Count active users in officer's council (with activity in last 30 days)
    active_users_count = sum(1 for u in council_members if not u.is_inactive_member())
    
    # Count inactive users in officer's council (members/officers with no activity in 30 days)
    inactive_users_count = sum(1 for u in council_members if u.is_inactive_member())
    
    # Total members in council (active + inactive)
    total_members = active_users_count + inactive_users_count
    
    # Get daily Bible verse
    daily_verse = get_daily_bible_verse()
    
    # Check if we need to show inactive warning popup
    show_inactive_warning = request.session.pop('show_inactive_warning', False)
    
    context = {
        'user': user,
        'user_list': user_list, 
        'events': events, 
        'approved_events_count': approved_events_count,
        'pending_events_count': pending_events_count,
        'analytics': analytics,
        'activities_count': activities_count,
        'user_recruitment_count': user_recruitment_count,
        'pending_users_count': pending_users_count,
        'active_users_count': active_users_count,
        'inactive_users_count': inactive_users_count,
        'total_members': total_members,
        'daily_verse': daily_verse,
        'show_inactive_warning': show_inactive_warning
    }
    
    return render(request, 'officer_dashboard.html', context)

def member_dashboard(request):
    """Dashboard view for members"""
    from datetime import date
    from ..bible_verses import get_daily_bible_verse
    today = date.today()
    
    user = request.user
    if not user.council:
        return redirect('dashboard')
    
    # Members see their council's current/future events and global events
    events = Event.objects.filter(
        (Q(council=user.council) | Q(is_global=True)) &
        Q(date_from__gte=today)
    )
    # Count only approved events
    approved_events_count = Event.objects.filter(
        (Q(council=user.council) | Q(is_global=True)) & 
        Q(status='approved', date_from__gte=today)
    ).count()
    
    # Get activities (events attended)
    activities_count = EventAttendance.objects.filter(member=user, is_present=True).count()
    
    # Calculate user's recruitment count
    user_recruitment_count = user.recruitments.count()
    
    # Get council announcements
    announcements = []
    council_updates = []
    if user.council:
        # TODO: Implement council announcements
        pass
    
    # Get forum messages
    forum_messages = ForumMessage.objects.all().order_by('-timestamp')[:5]
    
    # Get daily Bible verse
    daily_verse = get_daily_bible_verse()
    
    # Check if we need to show inactive warning popup
    show_inactive_warning = request.session.pop('show_inactive_warning', False)
    
    context = {
        'user': user,
        'events': events, 
        'approved_events_count': approved_events_count,
        'activities_count': activities_count,
        'announcements': announcements,
        'forum_messages': forum_messages,
        'council_updates': council_updates,
        'user_recruitment_count': user_recruitment_count,
        'daily_verse': daily_verse,
        'show_inactive_warning': show_inactive_warning
    }
    
    return render(request, 'member_dashboard.html', context)

def pending_dashboard(request):
    """Dashboard view for pending users"""
    logout(request)
    return redirect('sign-in')

@never_cache
@login_required
def edit_profile(request):
    user = request.user
    if request.method == 'POST':
        try:
            # Update user fields
            user.first_name = request.POST.get('first_name', user.first_name)
            user.second_name = request.POST.get('second_name', user.second_name)
            user.middle_name = request.POST.get('middle_name', user.middle_name)
            # Generate middle_initial from middle_name
            if user.middle_name:
                user.middle_initial = f"{user.middle_name[0]}."
            user.last_name = request.POST.get('last_name', user.last_name)
            user.suffix = request.POST.get('suffix', user.suffix)
            user.username = request.POST.get('username', user.username)
            user.street = request.POST.get('street', user.street)
            user.barangay = request.POST.get('barangay', user.barangay)
            user.city = request.POST.get('city', user.city)
            user.province = request.POST.get('province', user.province)
            user.zip_code = request.POST.get('zip_code', user.zip_code)
            user.contact_number = request.POST.get('contact_number', user.contact_number)
            user.gender = request.POST.get('gender', user.gender)
            user.religion = request.POST.get('religion', user.religion)

            # Update password if provided
            password = request.POST.get('password')
            if password:
                user.set_password(password)

            # Handle profile picture
            cropped_image = request.POST.get('cropped_image')
            if cropped_image:
                format, imgstr = re.match(r'data:image/(\w+);base64,(.+)', cropped_image).groups()
                image_data = base64.b64decode(imgstr)
                filename = f'{user.username}_profile.jpg'
                user.profile_picture.save(filename, ContentFile(image_data), save=False)

            user.save()
            messages.success(request, 'Profile updated successfully!')
            # Stay on the same page instead of redirecting
            return render(request, 'edit_profile.html', {'user': user})
        except Exception as e:
            messages.error(request, f'Error updating profile: {str(e)}')
    
    return render(request, 'edit_profile.html', {'user': user})

# @login_required
# def search_users(request):
#     query = request.GET.get('q')
#     results = []
#     if query:
#         results = User.objects.filter(username__icontains=query, is_archived=False).exclude(role='pending')
#     return render(request, 'search_results.html', {'results': results, 'query': query})

@login_required
def forum(request):
    if not request.user.is_authenticated or request.user.role == 'pending':
        return redirect('sign-in')
        
    categories = ForumCategory.objects.all()
    user_council = request.user.council
    context = {
        'categories': categories,
        'current_user': request.user,
        'user_council': user_council,
    }
    return render(request, 'forum/forum.html', context)

@login_required
def get_messages(request, category_id):
    category = get_object_or_404(ForumCategory, id=category_id)
    forum_type = request.GET.get('forum_type', 'council')  # Default to council (public)
    
    # Filter messages based on forum type
    if forum_type == 'district':
        # Private forum - only show messages from user's council
        messages = ForumMessage.objects.filter(
            category=category,
            council=request.user.council,
            is_district_forum=True
        ).select_related('sender', 'council').order_by('timestamp')
    else:
        # Public forum - show messages from all councils
        messages = ForumMessage.objects.filter(
            category=category,
            is_district_forum=False
        ).select_related('sender', 'council').order_by('timestamp')
    
    messages_data = []
    for msg in messages:
        profile_picture_url = msg.sender.profile_picture.url if msg.sender.profile_picture else None
        image_url = msg.image.url if msg.image else None
        
        messages_data.append({
            'id': msg.id,
            'content': msg.content,
            'sender': msg.sender.username,
            'sender_first_name': msg.sender.first_name,
            'sender_last_name': msg.sender.last_name,
            'sender_role': msg.sender.role,
            'council': msg.council.id,
            'timestamp': msg.timestamp.strftime('%m/%d/%y %H:%M'),
            'is_pinned': msg.is_pinned,
            'can_delete': request.user.role == 'admin' or request.user == msg.sender,
            'sender_profile_picture': profile_picture_url,
            'image_url': image_url,
        })
    
    return JsonResponse({'messages': messages_data})

@login_required
@csrf_protect
def send_message(request):
    if request.method == 'POST':
        try:
            category_id = request.POST.get('category_id')
            content = request.POST.get('content', '')
            image = request.FILES.get('image')
            forum_type = request.POST.get('forum_type', 'council')  # Default to council (public)
            
            category = get_object_or_404(ForumCategory, id=category_id)
            
            message = ForumMessage.objects.create(
                sender=request.user,
                category=category,
                content=content,
                council=request.user.council,
                is_district_forum=(forum_type == 'district')  # Set flag based on forum type
            )
            
            # Handle image upload if provided
            if image:
                message.image = image
                message.save()
            
            # Create notifications for other users
            if forum_type == 'district':
                # Only notify users in the same council for district messages
                other_users = User.objects.filter(
                    council=request.user.council
                ).exclude(id=request.user.id)
            else:
                # Notify all users for council messages
                other_users = User.objects.exclude(id=request.user.id)
            
            notifications = [
                Notification(user=user, message=message)
                for user in other_users
            ]
            Notification.objects.bulk_create(notifications)
            
            return JsonResponse({
                'status': 'success',
                'message_id': message.id,
                'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M')
            })
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    
    return JsonResponse({'status': 'error'}, status=400)

@login_required
@csrf_protect
def delete_message(request, message_id):
    message = get_object_or_404(ForumMessage, id=message_id)
    if request.user.role == 'admin' or request.user == message.sender:
        message.delete()
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error', 'message': 'Permission denied'}, status=403)

@login_required
@csrf_protect
def pin_message(request, message_id):
    if request.user.role not in ['admin', 'officer']:
        return JsonResponse({'status': 'error', 'message': 'Permission denied'}, status=403)
    
    message = get_object_or_404(ForumMessage, id=message_id)
    message.is_pinned = not message.is_pinned
    message.save()
    
    return JsonResponse({
        'status': 'success',
        'is_pinned': message.is_pinned
    })


@login_required
def get_notifications(request):
    """Get all notifications for the current user"""
    notifications = Notification.objects.filter(
        user=request.user
    ).select_related('message', 'message__sender', 'related_user', 'related_event', 'related_council').order_by('-timestamp')[:50]
    
    notifications_data = []
    for notif in notifications:
        # Determine notification type based on whether it has a message field
        # This is the ONLY reliable way to distinguish forum messages from system notifications
        if notif.message:
            # This is a forum message notification
            notification_type = 'forum_message'
            content = notif.message.content[:100] + '...' if len(notif.message.content) > 100 else notif.message.content
            title = f"Message from {notif.message.sender.first_name} {notif.message.sender.last_name}"
        else:
            # This is a system notification
            # Use the notification_type field, but ignore if it's the default 'forum_message'
            # (which means it was never explicitly set)
            if notif.notification_type and notif.notification_type != 'forum_message':
                notification_type = notif.notification_type
            else:
                # If no explicit type or default type, treat as generic system notification
                notification_type = 'system_notification'
            
            content = notif.content or ''
            title = notif.title or 'Notification'
        
        # Debug logging
        print(f"Notification ID: {notif.id}, Type: {notification_type}, Has Message: {bool(notif.message)}, DB Type: {notif.notification_type}")
        
        notifications_data.append({
            'id': notif.id,
            'title': title,
            'content': content,
            'is_read': notif.is_read,
            'timestamp': notif.timestamp.isoformat(),
            'notification_type': notification_type
        })
    
    return JsonResponse({'notifications': notifications_data})

@login_required
def mark_notification_read(request, notification_id):
    """Mark a single notification as read"""
    notification = get_object_or_404(Notification, id=notification_id, user=request.user)
    notification.is_read = True
    notification.save()
    return JsonResponse({'status': 'success'})

@login_required
def delete_notification(request, notification_id):
    """Delete a notification"""
    notification = get_object_or_404(Notification, id=notification_id, user=request.user)
    notification.delete()
    return JsonResponse({'status': 'success'})

@login_required
def mark_all_notifications_read(request):
    """Mark all notifications as read for the current user"""
    Notification.objects.filter(user=request.user, is_read=False).update(is_read=True)
    return JsonResponse({'status': 'success'})

@login_required
def delete_all_notifications(request):
    """Delete all notifications for the current user"""
    Notification.objects.filter(user=request.user).delete()
    return JsonResponse({'status': 'success'})

def member_list(request):
    """View for displaying a list of all members (for admin users)"""
    if request.user.role != 'admin':
        return redirect('dashboard')
    
    users = User.objects.filter(is_active=True).exclude(role='admin')
    
    # Filter by role if specified
    role_filter = request.GET.get('role', None)
    if role_filter and role_filter != 'all':
        users = users.filter(role=role_filter)
    
    # Filter by council if specified
    council_filter = request.GET.get('council', None)
    if council_filter and council_filter != 'all':
        users = users.filter(council_id=council_filter)
    
    # Filter by degree if specified
    degree_filter = request.GET.get('degree', None)
    if degree_filter and degree_filter != 'all':
        users = users.filter(current_degree=degree_filter)
    
    # Search by name if specified
    search_query = request.GET.get('search', None)
    if search_query:
        users = users.filter(
            Q(first_name__icontains=search_query) | 
            Q(last_name__icontains=search_query) |
            Q(email__icontains=search_query)
        )
    
    councils = Council.objects.all()
    
    context = {
        'users': users,
        'councils': councils,
        'role_filter': role_filter,
        'council_filter': council_filter,
        'degree_filter': degree_filter,
        'search_query': search_query,
    }
    
    return render(request, 'member_list.html', context)

def council_members(request):
    """View for displaying members of a specific council (for officer users)"""
    if request.user.role not in ['admin', 'officer']:
        return redirect('dashboard')
    
    # Officers can only see members of their own council
    if request.user.role == 'officer':
        council = request.user.council
        users = User.objects.filter(council=council, is_active=True)
    else:
        # Admin can see all members but can filter by council
        council_id = request.GET.get('council', None)
        if council_id:
            council = Council.objects.get(id=council_id)
            users = User.objects.filter(council=council, is_active=True)
        else:
            users = User.objects.filter(is_active=True)
            council = None
    
    # Filter by role if specified
    role_filter = request.GET.get('role', None)
    if role_filter and role_filter != 'all':
        users = users.filter(role=role_filter)
    
    # Filter by degree if specified
    degree_filter = request.GET.get('degree', None)
    if degree_filter and degree_filter != 'all':
        users = users.filter(current_degree=degree_filter)
    
    # Search by name if specified
    search_query = request.GET.get('search', None)
    if search_query:
        users = users.filter(
            Q(first_name__icontains=search_query) | 
            Q(last_name__icontains=search_query) |
            Q(email__icontains=search_query)
        )
    
    context = {
        'users': users,
        'council': council,
        'role_filter': role_filter,
        'degree_filter': degree_filter,
        'search_query': search_query,
    }
    
    return render(request, 'council_members.html', context)

@never_cache
@login_required
def council_events(request):
    """View for displaying events of a specific council (for officer users)"""
    if request.user.role not in ['admin', 'officer']:
        return redirect('dashboard')
    
    # Use timezone-aware date to ensure correct date comparison
    from django.utils import timezone
    today = timezone.localtime(timezone.now()).date()
    
    # Officers can only see events of their own council
    if request.user.role == 'officer':
        council = request.user.council
        # Get events for this council AND global events
        events = Event.objects.filter(
            Q(council=council) | Q(is_global=True)
        )
    else:
        # Admin can see all events but can filter by council
        council_id = request.GET.get('council', None)
        if council_id:
            council = Council.objects.get(id=council_id)
            events = Event.objects.filter(council=council)
        else:
            events = Event.objects.all()
            council = None
    
    # Filter by category if specified
    category_filter = request.GET.get('category', None)
    if category_filter and category_filter != 'all':
        events = events.filter(category=category_filter)
    
    # Get status filter
    status_filter = request.GET.get('status', None)
    
    # Mark events as today, upcoming, or past
    todays_events = []
    upcoming_events = []
    past_events = []
    rejected_events = []
    
    for event in events:
        # Check if the event is happening today (strict date match)
        # Event is only accessible on or after the start date, and on or before the end date
        event.is_today = (event.date_from <= today <= (event.date_until or event.date_from))
        
        # If filtering by status, only include matching events
        if status_filter and status_filter != 'all' and event.status != status_filter:
            continue
            
        # Categorize events by date and status
        if event.status == 'rejected':
            rejected_events.append(event)
        elif event.is_today:
            todays_events.append(event)
        elif event.date_from > today:
            upcoming_events.append(event)
        elif (event.date_until or event.date_from) < today:
            past_events.append(event)
    
    # Sort events: approved first, then by proximity to today
    def sort_key(event):
        # Primary sort: approved status (True/False)
        # Secondary sort: date proximity to today
        is_approved = event.status == 'approved'
        days_to_event = (event.date_from - today).days if event.date_from >= today else 1000
        return (-1 if is_approved else 0, days_to_event)
    
    # Sort upcoming events
    upcoming_events.sort(key=sort_key)
    
    # Sort today's events (approved first)
    todays_events.sort(key=lambda event: 0 if event.status == 'approved' else 1)
    
    # If filtering by rejected status, show rejected events in main list
    if status_filter == 'rejected':
        sorted_events = rejected_events
    else:
        # Combine events: today's events first, then upcoming
        sorted_events = todays_events + upcoming_events
    
    context = {
        'events': sorted_events,
        'past_events': past_events + rejected_events,  # Include rejected events with past events
        'council': council,
        'status_filter': status_filter,
        'category_filter': category_filter,
        'today': today,
        'has_todays_events': len(todays_events) > 0,
    }
    
    return render(request, 'council_events.html', context)

@never_cache
@login_required
def my_recruits(request):
    """View for displaying a user's recruits"""
    from django.utils import timezone
    from datetime import timedelta
    
    user = request.user
    
    # Get all recruitments by this user
    recruitments = Recruitment.objects.filter(recruiter=user).select_related('recruited').order_by('-date_recruited')
    
    # Get statistics
    total_recruits = recruitments.count()
    
    # Get recent recruitments (within the last month)
    one_month_ago = timezone.now().date() - timedelta(days=30)
    recent_recruitments = recruitments.filter(date_recruited__gte=one_month_ago)
    recent_recruits_count = recent_recruitments.count()
    
    # Get next degree requirements
    current_degree = user.current_degree or '1st'
    next_degree = None
    recruits_needed = 0
    needs_event_attendance = False
    
    if current_degree == '1st':
        next_degree = '2nd'
        recruits_needed = max(0, 1 - recent_recruits_count)
        needs_event_attendance = False
    elif current_degree == '2nd':
        next_degree = '3rd'
        recruits_needed = max(0, 3 - total_recruits)
        needs_event_attendance = True
    elif current_degree == '3rd':
        next_degree = '4th'
        recruits_needed = max(0, 5 - total_recruits)
        needs_event_attendance = True
    
    # Check if user has attended recent events
    has_recent_attendance = False
    if needs_event_attendance:
        has_recent_attendance = EventAttendance.objects.filter(
            member=user,
            is_present=True,
            event__date_from__gte=one_month_ago
        ).exists()
    
    context = {
        'recruitments': recruitments,
        'total_recruits': total_recruits,
        'recent_recruits': recent_recruits_count,
        'current_degree': user.get_current_degree_display() if user.current_degree else '1st Degree',
        'next_degree': dict(User.DEGREE_CHOICES).get(next_degree) if next_degree else None,
        'recruits_needed': recruits_needed,
        'needs_event_attendance': needs_event_attendance,
        'has_recent_attendance': has_recent_attendance,
    }
    
    return render(request, 'my_recruits.html', context)

def capstone_project(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('message')

        if not all([name, email, message]):
            return render(request, 'homepage.html', {'error': 'All fields are required.'})

        try:
            send_mail(
                subject=f'Contact Us Message from {name}',
                message=f'Name: {name}\nEmail: {email}\nMessage: {message}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=['cratoscms@gmail.com'],
                fail_silently=False,
            )
            logger.info(f"Contact form email sent from {email} to cratoscms@gmail.com")
            return render(request, 'homepage.html', {'success': 'Your message has been sent successfully!'})
        except Exception as e:
            logger.error(f"Failed to send contact form email: {str(e)}")
            return render(request, 'homepage.html', {'error': 'Failed to send message. Please try again.'})

    return render(request, 'homepage.html')

@never_cache
@login_required
def leaderboard(request):
    """Leaderboard view showing top recruiters"""
    from datetime import datetime, timedelta
    from django.utils import timezone
    
    # Calculate date 3 months ago
    three_months_ago = timezone.now() - timedelta(days=90)
    
    # Build base queryset - show all users globally for precise leaderboard
    recruiters_query = User.objects.filter(
        is_archived=False
    ).annotate(
        recruitment_count=Count('recruitments')
    ).filter(
        recruitment_count__gt=0
    ).select_related('council')
    
    # Order the results
    recruiters = recruiters_query.order_by('-recruitment_count', 'first_name')
    
    # Get all recruiters for the main leaderboard (not just top 10)
    top_recruiters = recruiters
    
    # Get current user's rank and stats
    user_rank = None
    user_recruitment_count = request.user.recruitments.count()
    
    if user_recruitment_count > 0:
        # Find user's rank in the filtered results
        recruiters_list = list(recruiters.values_list('id', flat=True))
        if request.user.id in recruiters_list:
            user_rank = recruiters_list.index(request.user.id) + 1
    
    # Get recent recruitments for activity feed - show all globally
    recent_recruitments_query = Recruitment.objects.select_related(
        'recruiter', 'recruited', 'recruiter__council'
    )
    
    recent_recruitments = recent_recruitments_query.order_by('-date_recruited')[:10]
    
    # Calculate stats for all councils for filtering functionality
    all_councils_stats = {}
    councils = Council.objects.all()
    
    for council in councils:
        # Active recruiters: users with at least 1 recruitment in last 3 months
        active_recruiters = User.objects.filter(
            council=council,
            is_archived=False,
            recruitments__date_recruited__gte=three_months_ago
        ).distinct()
        
        # All-time council recruiters for top recruiter calculation
        council_recruiters = User.objects.filter(
            council=council,
            is_archived=False
        ).annotate(
            recruitment_count=Count('recruitments')
        ).filter(
            recruitment_count__gt=0
        ).order_by('-recruitment_count')
        
        all_councils_stats[council.name] = {
            'total_recruiters': active_recruiters.count(),
            'total_recruitments': Recruitment.objects.filter(
                recruiter__council=council
            ).count(),
            'top_recruiter': council_recruiters.first() if council_recruiters else None
        }
    
    # Get council-specific stats for current user's council
    council_stats = None
    if request.user.council:
        council_stats = all_councils_stats.get(request.user.council.name, {
            'total_recruiters': 0,
            'total_recruitments': 0,
            'top_recruiter': None
        })
    
    # Calculate global stats for "All Councils" filter
    global_active_recruiters = User.objects.filter(
        is_archived=False,
        recruitments__date_recruited__gte=three_months_ago
    ).distinct().count()
    
    global_total_recruitments = Recruitment.objects.count()
    
    global_top_recruiter = User.objects.filter(
        is_archived=False
    ).annotate(
        recruitment_count=Count('recruitments')
    ).filter(
        recruitment_count__gt=0
    ).order_by('-recruitment_count').first()
    
    global_stats = {
        'total_recruiters': global_active_recruiters,
        'total_recruitments': global_total_recruitments,
        'top_recruiter': global_top_recruiter
    }
    
    # Add recruitment dates to top_recruiters for JavaScript filtering
    top_recruiters_with_dates = []
    for recruiter in top_recruiters:
        recruiter_data = {
            'user': recruiter,
            'recruitment_count': recruiter.recruitment_count,
            'recent_recruitments': list(recruiter.recruitments.filter(
                date_recruited__gte=three_months_ago
            ).values_list('date_recruited', flat=True)),
            'is_active': recruiter.recruitments.filter(
                date_recruited__gte=three_months_ago
            ).exists()
        }
        top_recruiters_with_dates.append(recruiter_data)
    
    # Convert stats to JSON-serializable format
    import json
    serializable_all_councils_stats = {}
    for council_name, stats in all_councils_stats.items():
        serializable_all_councils_stats[council_name] = {
            'total_recruiters': stats['total_recruiters'],
            'total_recruitments': stats['total_recruitments'],
            'top_recruiter': {
                'first_name': stats['top_recruiter'].first_name,
                'last_name': stats['top_recruiter'].last_name
            } if stats['top_recruiter'] else None
        }
    
    serializable_global_stats = {
        'total_recruiters': global_stats['total_recruiters'],
        'total_recruitments': global_stats['total_recruitments'],
        'top_recruiter': {
            'first_name': global_stats['top_recruiter'].first_name,
            'last_name': global_stats['top_recruiter'].last_name
        } if global_stats['top_recruiter'] else None
    }
    
    # Convert to JSON strings for safe template rendering
    all_councils_stats_json = json.dumps(serializable_all_councils_stats)
    global_stats_json = json.dumps(serializable_global_stats)

    context = {
        'top_recruiters': top_recruiters,
        'top_recruiters_with_dates': top_recruiters_with_dates,
        'user_rank': user_rank,
        'user_recruitment_count': user_recruitment_count,
        'recent_recruitments': recent_recruitments,
        'council_stats': serializable_global_stats,  # Use global stats as default display
        'all_councils_stats': all_councils_stats_json,
        'global_stats': global_stats_json,
        'three_months_ago': three_months_ago.isoformat(),
        'user': request.user
    }
    
    return render(request, 'leaderboard.html', context)

@login_required
def toggle_dark_mode(request):
    """Toggle dark mode for the current user"""
    if request.method == 'POST':
        try:
            user = request.user
            # Handle case where dark_mode field might not exist yet
            try:
                current_dark_mode = user.dark_mode
            except AttributeError:
                current_dark_mode = False
            
            user.dark_mode = not current_dark_mode
            user.save()
            return JsonResponse({
                'status': 'success',
                'dark_mode': user.dark_mode
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    return JsonResponse({'status': 'error'}, status=400)

# def member_attend(request):
#     return render(request, 'member_attend.html')
