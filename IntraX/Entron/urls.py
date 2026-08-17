from . import views
from django.urls import path
urlpatterns= [
    path('test/', views.test, name = "test"),
    path('login/', views.company_login, name = "company_login"),
    path('admin/', views.admin_login, name = "admin_login"),
    path('register/', views.register_admin, name = "register"),
    path("logout/", views.logout_view, name="logout_view"),
    path('dashboard/', views.dashboard, name = "dashboard"),
    path('alerts/', views.alerts_page, name='alerts_page'),
    path('alerts/<int:alert_id>/resolve/', views.resolve_alert, name='resolve_alert'),
    path('alerts/device/<uuid:device_id>/', views.device_alerts_page, name='device_alerts_page'),
    path('alerts/device/<uuid:device_id>/resolve-all/', views.resolve_all_alerts, name='resolve_all_alerts'),
    path('alerts/unassigned/', views.unassigned_alerts_page, name='unassigned_alerts_page'),
    path('alerts/unassigned/resolve-all/', views.resolve_all_unassigned, name='resolve_all_unassigned'),
    path('devices/', views.devices_page, name='devices_page'),
    path('devices/<uuid:device_id>/', views.device_detail, name='device_detail'),
    path('analytics/', views.analytics_page, name='analytics_page'),
    path('permissions/', views.permission_manager, name='permission_manager'),
    path('permissions/<int:user_id>/toggle/', views.toggle_admin_status, name='toggle_admin_status'),
    path('permissions/<int:user_id>/update/', views.update_admin_permissions, name='update_admin_permissions'),
    path('settings/', views.company_settings, name='company_settings'),
    path('settings/regenerate-key/', views.regenerate_registration_key, name='regenerate_registration_key'),
    path('settings/change-password/', views.change_company_password, name='change_company_password'),
    path('register_company/', views.register_company, name='register_company'),
    path('staff_login/', views.staff_login, name='staff_login'),

]