from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_pc, name='register_pc'),
    path('heartbeat/', views.heartbeat, name='heartbeat'),
    path('alerts/', views.alert, name='alert'),
]