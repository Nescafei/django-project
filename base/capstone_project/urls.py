from django.urls import path
from . import views

urlpatterns = [
    path('', views.capstone_project, name='capstone_project'),
    path('mission_vision/', views.mission_vision, name='mission_vision'),
    path('faith-action/', views.faith_action, name='faith-action'),
    path('councils/', views.councils, name='councils'),
    path('donations/', views.donations, name='donations'),
    path('sign-in/', views.sign_in, name='sign-in'),
    path('sign-up/', views.sign_up, name='sign-up'),
    path('about_us/', views.about_us, name='about_us'),
]