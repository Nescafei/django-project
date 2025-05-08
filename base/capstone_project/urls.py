from django.urls import path
from capstone_project import views

urlpatterns = [
    path('', views.capstone_project, name='capstone_project'),
    path('mission_vision/', views.mission_vision, name='mission_vision'),
    path('faith-action/', views.faith_action, name='faith-action'),
    path('councils/', views.councils, name='councils'),
    path('donations/', views.donations, name='donations'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('about_us/', views.about_us, name='about_us'),
    path('events-management/', views.events_management, name='events_management'),
    path('donation-reports/', views.donation_reports, name='donation_reports'),
    path('sign-in/', views.sign_in, name='sign-in'),
    path('sign-up/', views.sign_up, name='sign-up'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('pending-users/', views.manage_pending_users, name='manage_pending_users'),
    path('approve-user/<int:user_id>/', views.approve_user, name='approve_user'),
    path('reject-user/<int:user_id>/', views.reject_user, name='reject_user'),
    path('promote-user/<int:user_id>/', views.promote_user, name='promote_user'),
    path('demote-user/<int:user_id>/', views.demote_user, name='demote_user'),
    path('archive-user/<int:user_id>/', views.archive_user, name='archive_user'),
    # path('delete-user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('analytics-form/', views.analytics_form, name='analytics_form'),
    path('analytics-view/', views.analytics_view, name='analytics_view'),
    path('archived-users/', views.archived_users, name='archived_users'),
]