"""
Notification utilities for creating role-based notifications
"""
from .models import Notification, User
from datetime import date


def create_notification(user, title, content, notification_type, related_user=None, related_event=None, related_council=None):
    """
    Create a notification for a user
    
    Args:
        user: User object to receive the notification
        title: Notification title
        content: Notification content
        notification_type: Type of notification (from NOTIFICATION_TYPES)
        related_user: Related user (optional)
        related_event: Related event (optional)
        related_council: Related council (optional)
    """
    notification = Notification.objects.create(
        user=user,
        title=title,
        content=content,
        notification_type=notification_type,
        related_user=related_user,
        related_event=related_event,
        related_council=related_council
    )
    return notification


def notification_exists_today(user, notification_type, related_event=None):
    """
    Check if a notification of this type already exists for today
    
    Args:
        user: User object
        notification_type: Type of notification
        related_event: Related event (optional)
    
    Returns:
        True if notification exists today, False otherwise
    """
    today = date.today()
    query = Notification.objects.filter(
        user=user,
        notification_type=notification_type,
        timestamp__date=today
    )
    
    if related_event:
        query = query.filter(related_event=related_event)
    
    return query.exists()


def notify_admin_pending_proposal(user, proposal_type="member"):
    """Notify admin of pending proposal/member"""
    admins = User.objects.filter(role='admin', is_active=True)
    for admin in admins:
        create_notification(
            user=admin,
            title=f"New Pending {proposal_type.title()}",
            content=f"{user.first_name} {user.last_name} has submitted a pending {proposal_type} request.",
            notification_type='pending_proposal',
            related_user=user
        )


def notify_admin_donation_received(donation_amount, donor_name):
    """Notify admin of received donation"""
    admins = User.objects.filter(role='admin', is_active=True)
    for admin in admins:
        create_notification(
            user=admin,
            title="Donation Received",
            content=f"A donation of ₱{donation_amount} has been received from {donor_name}.",
            notification_type='donation_received'
        )


def notify_admin_event_today(event):
    """Notify admin of event happening today"""
    admins = User.objects.filter(role='admin', is_active=True)
    for admin in admins:
        # Check if notification already exists today for this event
        if not notification_exists_today(admin, 'event_today', related_event=event):
            create_notification(
                user=admin,
                title="Event Happening Today",
                content=f"The event '{event.name}' is happening today.",
                notification_type='event_today',
                related_event=event
            )


def notify_officer_event_today(event):
    """Notify officers of event happening today in their council"""
    officers = User.objects.filter(council=event.council, role='officer', is_active=True)
    for officer in officers:
        # Check if notification already exists today for this event
        if not notification_exists_today(officer, 'event_today', related_event=event):
            create_notification(
                user=officer,
                title="Event Happening Today",
                content=f"The event '{event.name}' is happening today in your council.",
                notification_type='event_today',
                related_event=event,
                related_council=event.council
            )


def notify_member_event_today(event):
    """Notify members of event happening today in their council"""
    members = User.objects.filter(council=event.council, role='member', is_active=True)
    for member in members:
        # Check if notification already exists today for this event
        if not notification_exists_today(member, 'event_today', related_event=event):
            create_notification(
                user=member,
                title="Event Happening Today",
                content=f"The event '{event.name}' is happening today in your council.",
                notification_type='event_today',
                related_event=event,
                related_council=event.council
            )


def notify_admin_donation_quota_reached(council, quota_amount):
    """Notify admin when donation quota is reached"""
    admins = User.objects.filter(role='admin', is_active=True)
    for admin in admins:
        create_notification(
            user=admin,
            title="Donation Quota Reached",
            content=f"The {council.name} council has reached its donation quota of ₱{quota_amount}.",
            notification_type='donation_quota_reached',
            related_council=council
        )


def notify_officer_proposal_status(officer, event, status):
    """Notify officer of proposal acceptance/rejection"""
    notification_type = 'proposal_accepted' if status == 'approved' else 'proposal_rejected'
    title = "Event Proposal Accepted" if status == 'approved' else "Event Proposal Rejected"
    content = f"Your event proposal '{event.name}' has been {status}." if status == 'approved' else f"Your event proposal '{event.name}' has been rejected."
    
    create_notification(
        user=officer,
        title=title,
        content=content,
        notification_type=notification_type,
        related_event=event
    )


def notify_officer_pending_member(officer, member):
    """Notify officer of pending member in their council"""
    create_notification(
        user=officer,
        title="Pending Member Approval",
        content=f"{member.first_name} {member.last_name} is pending approval in your council.",
        notification_type='pending_member_approval',
        related_user=member,
        related_council=officer.council
    )


def notify_user_inactive(user):
    """Notify user of inactivity"""
    notification_type = 'officer_inactive' if user.role == 'officer' else 'member_inactive'
    create_notification(
        user=user,
        title="Inactivity Notice",
        content="You have been inactive. Please update your profile or participate in events.",
        notification_type=notification_type
    )


def notify_user_council_moved(user, new_council, old_council):
    """Notify user of council transfer"""
    notification_type = 'council_moved' if user.role == 'officer' else 'member_moved'
    create_notification(
        user=user,
        title="Council Transfer",
        content=f"You have been moved from {old_council.name} to {new_council.name}.",
        notification_type=notification_type,
        related_council=new_council
    )


def notify_user_promotion(user, new_role):
    """Notify user of promotion"""
    if new_role == 'officer':
        notification_type = 'promoted_to_officer'
        title = "Promotion to Officer"
        content = "Congratulations! You have been promoted to Officer."
    else:
        notification_type = 'member_promoted'
        title = "Promotion"
        content = "Congratulations! You have been promoted."
    
    create_notification(
        user=user,
        title=title,
        content=content,
        notification_type=notification_type
    )


def notify_user_demotion(user, old_role):
    """Notify user of demotion"""
    notification_type = 'demoted_to_member' if old_role == 'officer' else 'member_demoted'
    create_notification(
        user=user,
        title="Role Change",
        content="You have been demoted to Member.",
        notification_type=notification_type
    )


def notify_user_recruiter_assigned(user, recruiter):
    """Notify user of being assigned as recruiter"""
    notification_type = 'recruiter_assigned' if user.role == 'officer' else 'member_recruiter'
    create_notification(
        user=user,
        title="Recruiter Assignment",
        content=f"You have been assigned as a recruiter for {recruiter.first_name} {recruiter.last_name}.",
        notification_type=notification_type,
        related_user=recruiter
    )


def notify_user_event_attended(user, event):
    """Notify user of event attendance"""
    notification_type = 'event_attended' if user.role == 'member' else 'event_attended'
    create_notification(
        user=user,
        title="Event Attendance Recorded",
        content=f"Your attendance for '{event.name}' has been recorded.",
        notification_type=notification_type,
        related_event=event
    )


def notify_recruiter_manual_assignment(recruiter, recruit):
    """Notify recruiter that they have been assigned a recruit manually by admin"""
    notification_type = 'recruiter_assigned' if recruiter.role == 'officer' else 'member_recruiter'
    create_notification(
        user=recruiter,
        title="New Recruit Assigned",
        content=f"You have been assigned {recruit.first_name} {recruit.last_name} as a recruit by the admin.",
        notification_type=notification_type,
        related_user=recruit
    )


def notify_recruit_manual_assignment(recruit, recruiter):
    """Notify recruit that they have been assigned a recruiter manually by admin"""
    notification_type = 'recruiter_assigned' if recruit.role == 'officer' else 'member_recruiter'
    create_notification(
        user=recruit,
        title="Recruiter Assignment",
        content=f"You have been assigned {recruiter.first_name} {recruiter.last_name} as your recruiter by the admin.",
        notification_type=notification_type,
        related_user=recruiter
    )
