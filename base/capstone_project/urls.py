from django.urls import path
from capstone_project.more_views import views,donation, ledger, event_management, user_management, attendance, analytics, council

urlpatterns = [
    path('', views.capstone_project, name='capstone_project'),
    path('sign-in/', views.sign_in, name='sign-in'),
    path('sign-up/', views.sign_up, name='sign-up'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('pending-users/', user_management.manage_pending_users, name='manage_pending_users'),
    path('approve-user/<int:user_id>/', user_management.approve_user, name='approve_user'),
    path('reject-user/<int:user_id>/', user_management.reject_user, name='reject_user'),
    path('promote-user/<int:user_id>/', user_management.promote_user, name='promote_user'),
    path('demote-user/<int:user_id>/', user_management.demote_user, name='demote_user'),
    path('archive-user/<int:user_id>/', user_management.archive_user, name='archive_user'),
    path('analytics-form/', analytics.analytics_form, name='analytics_form'),
    path('analytics-view/', analytics.analytics_view, name='analytics_view'),
    path('archived-users/', user_management.archived_users, name='archived_users'),
    path('mission_vision/', views.mission_vision, name='mission_vision'),
    path('faith-action/', views.faith_action, name='faith-action'),
    path('councils/', views.councils, name='councils'),
    path('council/<int:council_id>/', views.council_detail, name='council_detail'),
    path('about_us/', views.about_us, name='about_us'),
    path('events-management/', views.events_management, name='events_management'),

    # Blockchain / Ledger
    path('blockchain/', ledger.get_blockchain_data, name='blockchain'),
    path('download-ledger/', ledger.download_ledger, name='download_ledger'),
    
    # Donations
    path('donations/', donation.donations, name='donations'),
    path('donation-reports/', views.donation_reports, name='donation_reports'),
    path('manual_donation/', donation.manual_donation, name='manual_donation'),
    path('review_manual_donations/', donation.review_manual_donations, name='review_manual_donations'),
    path('gcash/initiate', donation.initiate_gcash_payment, name='initiate_gcash_payment'),
    path('success/', donation.success_page, name='success_page'),
    path('cancel/', donation.cancel_page, name='cancel_page'),
    path('gcash/confirm/', donation.confirm_gcash_payment, name='confirm_gcash_payment'),

    # path('search-users/', views.search_users, name='search_users'),

    # New endpoint for recruiter name autocomplete
    path('search-members/', user_management.search_members, name='search_members'),

    # Username and email validation endpoints
    path('check-username/', user_management.check_username, name='check_username'),
    path('check-email/', user_management.check_email, name='check_email'),

    path('forum/', views.forum, name='forum'),
    path('forum/messages/<int:category_id>/', views.get_messages, name='get_messages'),
    path('forum/send/', views.send_message, name='send_message'),
    path('forum/delete/<int:message_id>/', views.delete_message, name='delete_message'),
    path('forum/pin/<int:message_id>/', views.pin_message, name='pin_message'),

    # URLs for role management and events
    path('manage-roles/', user_management.manage_roles, name='manage_roles'),
    path('add-event/', event_management.add_event, name='add_event'),
    path('edit-event/<int:event_id>/', event_management.edit_event, name='edit_event'),
    path('event-proposals/', event_management.event_proposals, name='event_proposals'),
    path('approve-event/<int:event_id>/', event_management.approve_event, name='approve_event'),
    path('reject-event/<int:event_id>/', event_management.reject_event, name='reject_event'),
    path('event/<int:event_id>/details/', event_management.event_details, name='event_details'),
    path('archived-events/', event_management.archived_events, name='archived_events'),
    
    # New URLs for member and event lists
    path('event-list/', event_management.event_list, name='event_list'),
    path('member-list/', views.member_list, name='member_list'),
    path('council-members/', views.council_members, name='council_members'),
    path('council-events/', views.council_events, name='council_events'),
    path('update-degree/<int:user_id>/', user_management.update_degree, name='update_degree'),
    
    # User details endpoint
    path('user/<int:user_id>/details/', user_management.user_details, name='user_details'),
    
    # Event attendance management
    path('event/<int:event_id>/attendance/', attendance.event_attendance, name='event_attendance'),
    path('event/update-attendance/', attendance.update_attendance, name='update_attendance'),

    # Member activities
    path('member-activities/', user_management.member_activities, name='member_activities'),
    
    # My Recruits
    path('my-recruits/', views.my_recruits, name='my_recruits'),
    
    # Add Recruitment Record
    path('add-recruitment/', user_management.add_recruitment, name='add_recruitment'),
    
    # Undo Recruitment Change
    path('undo-recruitment/<int:history_id>/', user_management.undo_recruitment, name='undo_recruitment'),

    # Change Council
    path('change-council/<int:user_id>/', user_management.change_council, name='change_council'),
    
    # Leaderboard
    path('leaderboard/', views.leaderboard, name='leaderboard'),
    
    # Attendance for solid ahh members
    path('member_attend/', attendance.member_attend, name='member_attend'),
    path('officer-take-attendance/', attendance.officer_take_attendance, name='officer_take_attendance'),
    path('scan-qr/', attendance.scan_qr, name='scan_qr'),

    # Council Management
    path('manage-councils/', council.manage_councils, name='manage_councils'),
    path('add-council/', council.add_council, name='add_council'),
    path('delete-council/<int:council_id>/', council.delete_council, name='delete_council'),
    path('edit-council/<int:council_id>/', council.edit_council, name='edit_council'),
]