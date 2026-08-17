from datetime import timedelta, datetime
from functools import wraps
import secrets
from django.contrib import messages
from django.shortcuts import render, redirect

from django.http import HttpResponse
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from django.db.models import Count, Avg, Q, Max
from django.db.models.functions import TruncHour, TruncDate, ExtractHour
from django.core.paginator import Paginator

from .models import Company, User, Device, Alert

def test(request):
    return HttpResponse("Hello !")
def staff_login(request):

    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None and user.is_staff:
            login(request, user)
            return redirect('register_company')
        else:
            messages.error(request, "Invalid staff username or password")
    return render(request, 'Entron/staff_login.html')
def register_company(request):
    if not (request.user.is_authenticated and request.user.is_staff):
        messages.error(request, "Staff sign-in required to register a company.")
        return redirect('admin_login')

    if request.method == "POST":
        name = request.POST.get('name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password') 
        if Company.objects.filter(username=username).exists():
            messages.error(request, "That company username is already taken")
            return redirect('register_company')
        if password != confirm_password:
            messages.error(request, "Passwords don't match.")
            return redirect('register_company')
        if len(password or '') < 8:
            messages.error(request, "Password must be at least 8 characters.")
            return redirect('register_company')

        prefix = secrets.token_hex(6)
        secret = secrets.token_hex(16)
        raw_key = f"{prefix}.{secret}"
        Company.objects.create(
            name=name,
            username=username,
            email=email,
            password=make_password(password),
            registration_key=make_password(raw_key),
            registration_key_prefix=prefix,)
        messages.success(request, "Company Registered Successfully")
        return redirect('register_company')
    return render(request, 'Entron/register_company.html')
 
def company_login(request):
    if request.method == "POST":
        username = request.POST.get(('username'))
        password = request.POST.get('password')
        company = Company.objects.filter(username=username).first()

        if company and company.password and check_password(password, company.password):
            request.session["company_id"] = str(company.id)
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid Username or password")
    return render(request, 'Entron/company_login.html')


def admin_login(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid Username or Password")
    return render(request, 'Entron/admin_login.html')


def is_company_owner(request):
    if request.user.is_authenticated:
        return False
    return bool(request.session.get("company_id"))
def owner_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not is_company_owner(request):
            messages.error(request, "Only the company owner can access this page.")
            return redirect('dashboard')
        return view_func(request, *args, **kwargs)
    return _wrapped


def has_permission(request, field_name):
    if is_company_owner(request):
        return True
    return bool(request.user.is_authenticated and getattr(request.user, field_name, False))

def permission_required(field_name):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if not has_permission(request, field_name):
                messages.error(request, "You don't have permission to do this.")
                return redirect('dashboard')
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator


def company_login_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if get_current_company(request) is None:
            messages.error(request, "Please sign in to view this page.")
            return redirect('admin_login')
        return view_func(request, *args, **kwargs)
    return _wrapped


@permission_required('can_add_admins')
def register_admin(request):
    company = Company.objects.filter(id=request.session.get("company_id")).first()
    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
            return redirect('register')
        user = User.objects.create_user(
            username=username,
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=password,
            company=company)
        user.save()
        messages.success(request, "Administration registered successfully")
        return redirect('register')
    return render(request, 'Entron/register_admin.html', {"company": company})


def logout_view(request):
    request.session.flush()
    logout(request)
    return redirect('admin_login')


def get_current_company(request):
    if request.user.is_authenticated and getattr(request.user, "company_id", None):
        return request.user.company
    company_id = request.session.get("company_id")
    if company_id:
        return Company.objects.filter(id=company_id).first()
    return None


@company_login_required
def dashboard(request):
    company = get_current_company(request)
    devices = Device.objects.filter(company=company)
    alerts = Alert.objects.filter(company=company)
    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    devices_online = devices.filter(status=True).count()
    devices_offline = devices.filter(status=False).count()
    total_devices = devices.count()
    active_threats = alerts.filter(status="Pending").count()
    total_alerts = alerts.count()
    todays_alerts = alerts.filter(created_at__gte=today_start).count()
    critical_alerts = alerts.filter(severity="High").count()

    avg_cpu = devices.aggregate(avg=Avg('cpu_usage'))['avg'] or 0
    avg_ram = devices.aggregate(avg=Avg('ram_usage'))['avg'] or 0
    per_hour_qs = (
        alerts.filter(created_at__gte=last_24h)
        .annotate(hour=TruncHour('created_at'))
        .values('hour').annotate(count=Count('id')).order_by('hour'))
    attacks_per_hour = {
        "labels": [row['hour'].strftime('%H:%M') for row in per_hour_qs],
        "data": [row['count'] for row in per_hour_qs],}
    per_day_qs = (
        alerts.filter(created_at__gte=last_7d)
        .annotate(day=TruncDate('created_at'))
        .values('day')
        .annotate(count=Count('id'))
        .order_by('day'))
    attacks_by_day = {
        "labels": [row['day'].strftime('%b %d') for row in per_day_qs],
        "data": [row['count'] for row in per_day_qs],}
    distribution_qs = (
        alerts.values('attack_type')
        .annotate(count=Count('id'))
        .order_by('-count')[:8])
    attack_distribution = {
        "labels": [row['attack_type'] or "Unknown" for row in distribution_qs],
        "data": [row['count'] for row in distribution_qs],}

    device_health = {
        "labels": ["Online", "Offline"],
        "data": [devices_online, devices_offline],}
    timeline_qs = (
        alerts.filter(created_at__gte=last_7d)
        .annotate(day=TruncDate('created_at'))
        .values('day', 'severity')
        .annotate(count=Count('id'))
        .order_by('day'))
    timeline_days = sorted({row['day'] for row in timeline_qs})
    severities = ["Low", "Medium", "High"]
    timeline_map = {(row['day'], row['severity']): row['count'] for row in timeline_qs}
    threat_timeline = {
        "labels": [d.strftime('%b %d') for d in timeline_days],
        "series": [
            {
                "label": sev,
                "data": [timeline_map.get((d, sev), 0) for d in timeline_days],}
            for sev in severities
        ],}
    live_alert_devices = (
        alerts
        .values('device__device_id', 'device__name')
        .annotate(
            total=Count('id'),
            pending=Count('id', filter=Q(status="Pending")),
            high=Count('id', filter=Q(severity="High")),
            medium=Count('id', filter=Q(severity="Medium")),
            low=Count('id', filter=Q(severity="Low")),
            last_alert=Max('created_at'),
        )
        .order_by('-last_alert')[:10]
    )
    recent_devices = devices.order_by('-last_seen')[:10]
    context = {
        "company": company,
        "active_page": "dashboard",
        "is_owner": is_company_owner(request),
        "can_add_admins": has_permission(request, 'can_add_admins'),
        "can_manage_settings": has_permission(request, 'can_manage_settings'),
        "devices_online": devices_online,
        "devices_offline": devices_offline,
        "total_devices": total_devices,
        "active_threats": active_threats,
        "total_alerts": total_alerts,
        "todays_alerts": todays_alerts,
        "critical_alerts": critical_alerts,
        "avg_cpu": round(avg_cpu, 1),
        "avg_ram": round(avg_ram, 1),
        "live_alert_devices": live_alert_devices,
        "recent_devices": recent_devices,
        "attacks_per_hour": attacks_per_hour,
        "attacks_by_day": attacks_by_day,
        "attack_distribution": attack_distribution,
        "device_health": device_health,
        "threat_timeline": threat_timeline,
    }
    return render(request, 'Entron/dashboard.html', context)
def _resolve_company_or_fallback(request):
    return get_current_company(request)

@company_login_required
def alerts_page(request):
    company = _resolve_company_or_fallback(request)
    alerts = Alert.objects.filter(company=company)
    severity_filter = request.GET.get('severity')
    status_filter = request.GET.get('status')
    device_filter = request.GET.get('device')
    if severity_filter in {"Low", "Medium", "High"}:
        alerts = alerts.filter(severity=severity_filter)
    if status_filter in {"Pending", "Resolved"}:
        alerts = alerts.filter(status=status_filter)
    if device_filter:
        alerts = alerts.filter(device_id=device_filter)
    device_rows = (
        alerts.filter(device__isnull=False)
        .values('device__device_id', 'device__name')
        .annotate(
            total=Count('id'),
            pending=Count('id', filter=Q(status="Pending")),
            high=Count('id', filter=Q(severity="High")),
            medium=Count('id', filter=Q(severity="Medium")),
            low=Count('id', filter=Q(severity="Low")),
            last_alert=Max('created_at'),
        )
        .order_by('-pending', '-last_alert'))

    unassigned_count = alerts.filter(device__isnull=True).count()
    unassigned_pending = alerts.filter(device__isnull=True, status="Pending").count()
    all_devices = Device.objects.filter(company=company).order_by('name')
    context = {
        "company": company,
        "active_page": "alerts",
        "is_owner": is_company_owner(request),
        "can_add_admins": has_permission(request, 'can_add_admins'),
        "can_manage_settings": has_permission(request, 'can_manage_settings'),
        "device_rows": device_rows,
        "unassigned_count": unassigned_count,
        "unassigned_pending": unassigned_pending,
        "all_devices": all_devices,
        "severity_filter": severity_filter or "",
        "status_filter": status_filter or "",
        "device_filter": device_filter or "",}
    return render(request, 'Entron/alerts.html', context)

@company_login_required
def device_alerts_page(request, device_id):
    company = _resolve_company_or_fallback(request)
    device = Device.objects.filter(device_id=device_id, company=company).first()
    if device is None:
        messages.error(request, "Device not found.")
        return redirect('alerts_page')
    alerts = Alert.objects.filter(company=company, device=device).order_by('-created_at')
    severity_filter = request.GET.get('severity')
    status_filter = request.GET.get('status')
    if severity_filter in {"Low", "Medium", "High"}:
        alerts = alerts.filter(severity=severity_filter)
    if status_filter in {"Pending", "Resolved"}:
        alerts = alerts.filter(status=status_filter)
    pending_count = Alert.objects.filter(company=company, device=device, status="Pending").count()
    paginator = Paginator(alerts, 25)
    alerts_page = paginator.get_page(request.GET.get('page'))
    querystring = request.GET.copy()
    querystring.pop('page', None)
    context = {
        "company": company,
        "active_page": "alerts",
        "is_owner": is_company_owner(request),
        "can_add_admins": has_permission(request, 'can_add_admins'),
        "can_manage_settings": has_permission(request, 'can_manage_settings'),
        "can_manage_alerts": has_permission(request, 'can_manage_alerts'),
        "device": device,
        "alerts": alerts_page,
        "pending_count": pending_count,
        "severity_filter": severity_filter or "",
        "status_filter": status_filter or "",
        "querystring": querystring.urlencode(),
    }
    return render(request, 'Entron/device_alerts.html', context)


@permission_required('can_manage_alerts')
def resolve_all_alerts(request, device_id):
    if request.method != "POST":
        return HttpResponse(status=405)
    company = _resolve_company_or_fallback(request)
    device = Device.objects.filter(device_id=device_id, company=company).first()
    if device is None:
        messages.error(request, "Device not found.")
        return redirect('alerts_page')
    updated = Alert.objects.filter(company=company, device=device, status="Pending").update(status="Resolved")
    messages.success(request, f"Resolved {updated} alert(s) for {device.name}.")
    return redirect('device_alerts_page', device_id=device.device_id)
@company_login_required
def unassigned_alerts_page(request):
    company = _resolve_company_or_fallback(request)
    alerts = Alert.objects.filter(company=company, device__isnull=True).order_by('-created_at')
    pending_count = alerts.filter(status="Pending").count()
    paginator = Paginator(alerts, 25)
    alerts_page = paginator.get_page(request.GET.get('page'))
    context = {
        "company": company,
        "active_page": "alerts",
        "is_owner": is_company_owner(request),
        "can_add_admins": has_permission(request, 'can_add_admins'),
        "can_manage_settings": has_permission(request, 'can_manage_settings'),
        "can_manage_alerts": has_permission(request, 'can_manage_alerts'),
        "alerts": alerts_page,
        "pending_count": pending_count,
    }
    return render(request, 'Entron/unassigned_alerts.html', context)

@permission_required('can_manage_alerts')
def resolve_all_unassigned(request):
    if request.method != "POST":
        return HttpResponse(status=405)
    company = _resolve_company_or_fallback(request)
    if company is None:
        return redirect('alerts_page')
    updated = Alert.objects.filter(company=company, device__isnull=True, status="Pending").update(status="Resolved")
    messages.success(request, f"Resolved {updated} unassigned alert(s).")
    return redirect('unassigned_alerts_page')


@permission_required('can_manage_alerts')
def resolve_alert(request, alert_id):
    if request.method != "POST":
        return HttpResponse(status=405)
    company = _resolve_company_or_fallback(request)
    alert = Alert.objects.filter(id=alert_id, company=company).first()
    if alert is None:
        messages.error(request, "Alert not found.")
        return redirect('alerts_page')
    alert.status = "Resolved"
    alert.save()
    messages.success(request, f"Alert #{alert.id} marked resolved.")
    return redirect('alerts_page')

@company_login_required
def devices_page(request):
    company = _resolve_company_or_fallback(request)
    devices = Device.objects.filter(company=company).order_by('-last_seen')
    paginator = Paginator(devices, 20)
    devices_page_obj = paginator.get_page(request.GET.get('page'))
    context = {
        "company": company,
        "active_page": "devices",
        "is_owner": is_company_owner(request),
        "can_add_admins": has_permission(request, 'can_add_admins'),
        "can_manage_settings": has_permission(request, 'can_manage_settings'),
        "devices": devices_page_obj,}
    return render(request, 'Entron/devices.html', context)


@company_login_required
def device_detail(request, device_id):
    company = _resolve_company_or_fallback(request)
    device = Device.objects.filter(device_id=device_id, company=company).first()
    if device is None:
        messages.error(request, "Device not found.")
        return redirect('devices_page')
    alerts = Alert.objects.filter(company=company, device=device).order_by('-created_at')
    pending_qs = alerts.filter(status="Pending")
    context = {
        "company": company,
        "active_page": "devices",
        "is_owner": is_company_owner(request),
        "can_add_admins": has_permission(request, 'can_add_admins'),
        "can_manage_settings": has_permission(request, 'can_manage_settings'),
        "can_manage_alerts": has_permission(request, 'can_manage_alerts'),
        "device": device,
        "alerts": alerts[:100],
        "pending_count": pending_qs.count(),
        "total_alert_count": alerts.count(),
        "is_secure": not pending_qs.exists(),
    }
    return render(request, 'Entron/device_detail.html', context)

@company_login_required
def analytics_page(request):
    company = _resolve_company_or_fallback(request)
    alerts = Alert.objects.filter(company=company)
    range_preset = request.GET.get('range', 'all')
    start_date_str = request.GET.get('start_date') or ''
    end_date_str = request.GET.get('end_date') or ''
    now = timezone.now()
    start_dt = None
    end_dt = None
    if start_date_str and end_date_str:
        try:
            start_dt = timezone.make_aware(datetime.strptime(start_date_str, '%Y-%m-%d'))
            end_dt = timezone.make_aware(datetime.strptime(end_date_str, '%Y-%m-%d')) + timedelta(days=1)
            range_preset = 'custom'
        except ValueError:
            start_dt = end_dt = None
    elif range_preset == 'today':
        start_dt = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end_dt = now
    elif range_preset == '7d':
        start_dt = now - timedelta(days=7)
        end_dt = now
    elif range_preset == '30d':
        start_dt = now - timedelta(days=30)
        end_dt = now
    elif range_preset == 'month':
        start_dt = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end_dt = now
    if start_dt and end_dt:
        alerts = alerts.filter(created_at__gte=start_dt, created_at__lte=end_dt)
    total_alerts = alerts.count()
    severity_qs = alerts.values('severity').annotate(count=Count('id'))
    severity_map = {row['severity']: row['count'] for row in severity_qs}
    severity_breakdown = {
        "labels": ["Low", "Medium", "High"],
        "data": [severity_map.get("Low", 0), severity_map.get("Medium", 0), severity_map.get("High", 0)],
    }
    top_devices_qs = (
        alerts.filter(device__isnull=False)
        .values('device__name')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )
    top_devices = {
        "labels": [row['device__name'] for row in top_devices_qs],
        "data": [row['count'] for row in top_devices_qs],
    }
    confidence_buckets = [("<60%", 0, 60), ("60-80%", 60, 80), ("80-95%", 80, 95), ("95-100%", 95, 100.0001)]
    bucket_labels, bucket_data = [], []
    for label, low, high in confidence_buckets:
        bucket_labels.append(label)
        bucket_data.append(alerts.filter(confidence__gte=low, confidence__lt=high).count())
    confidence_distribution = {"labels": bucket_labels, "data": bucket_data}
    avg_confidence = alerts.aggregate(avg=Avg('confidence'))['avg'] or 0
    top_attack_qs = (
        alerts.values('attack_type')
        .annotate(count=Count('id'))
        .order_by('-count')
        .first())
    top_attack_name = top_attack_qs['attack_type'] if top_attack_qs else "—"
    top_attack_count = top_attack_qs['count'] if top_attack_qs else 0
    top_device_qs = (
        alerts.filter(device__isnull=False)
        .values('device__name')
        .annotate(count=Count('id'))
        .order_by('-count')
        .first())
    top_device_name = top_device_qs['device__name'] if top_device_qs else "—"
    top_device_count = top_device_qs['count'] if top_device_qs else 0
    resolved_count = alerts.filter(status="Resolved").count()
    resolution_rate = round((resolved_count / total_alerts * 100), 1) if total_alerts else 0
    hourly_qs = (
        alerts.annotate(hour=ExtractHour('created_at'))
        .values('hour')
        .annotate(count=Count('id'))
        .order_by('hour'))
    hourly_map = {row['hour']: row['count'] for row in hourly_qs}
    hourly_activity = {
        "labels": [f"{h:02d}:00" for h in range(24)],
        "data": [hourly_map.get(h, 0) for h in range(24)],}

    context = {
        "company": company,
        "active_page": "analytics",
        "is_owner": is_company_owner(request),
        "can_add_admins": has_permission(request, 'can_add_admins'),
        "can_manage_settings": has_permission(request, 'can_manage_settings'),
        "range_preset": range_preset,
        "start_date": start_date_str,
        "end_date": end_date_str,
        "severity_breakdown": severity_breakdown,
        "top_devices": top_devices,
        "confidence_distribution": confidence_distribution,
        "hourly_activity": hourly_activity,
        "avg_confidence": round(avg_confidence, 1),
        "total_alerts": total_alerts,
        "top_attack_name": top_attack_name,
        "top_attack_count": top_attack_count,
        "top_device_name": top_device_name,
        "top_device_count": top_device_count,
        "resolution_rate": resolution_rate,
        "resolved_count": resolved_count,}
    return render(request, 'Entron/analytics.html', context)

@owner_required
def permission_manager(request):
    company = _resolve_company_or_fallback(request)
    if company is None:
        return HttpResponse("No company exists yet.")
    admins = User.objects.filter(company=company).order_by('-date_joined')
    context = {
        "company": company,
        "active_page": "permissions",
        "is_owner": True,
        "can_add_admins": True,
        "can_manage_settings": True,
        "admins": admins,}
    return render(request, 'Entron/permissions.html', context)

@owner_required
def toggle_admin_status(request, user_id):
    if request.method != "POST":
        return HttpResponse(status=405)
    company = _resolve_company_or_fallback(request)
    target = User.objects.filter(id=user_id, company=company).first()
    if target is None:
        messages.error(request, "Administrator not found.")
        return redirect('permission_manager')
    target.is_active = not target.is_active
    target.save()
    state = "enabled" if target.is_active else "disabled"
    messages.success(request, f"Access {state} for {target.username}.")
    return redirect('permission_manager')

@owner_required
def update_admin_permissions(request, user_id):    
    if request.method != "POST":
        return HttpResponse(status=405)
    company = _resolve_company_or_fallback(request)
    target = User.objects.filter(id=user_id, company=company).first()
    if target is None:
        messages.error(request, "Administrator not found.")
        return redirect('permission_manager')
    target.can_manage_alerts = 'can_manage_alerts' in request.POST
    target.can_manage_devices = 'can_manage_devices' in request.POST
    target.can_add_admins = 'can_add_admins' in request.POST
    target.can_manage_settings = 'can_manage_settings' in request.POST
    target.save()
    messages.success(request, f"Updated permissions for {target.username}.")
    return redirect('permission_manager')

@permission_required('can_manage_settings')
def company_settings(request):
    company = _resolve_company_or_fallback(request)
    if company is None:
        return HttpResponse("No company exists yet.")
    new_registration_key = request.session.pop('new_registration_key', None)
    context = {
        "company": company,
        "active_page": "settings",
        "is_owner": is_company_owner(request),
        "can_manage_settings": True,
        "new_registration_key": new_registration_key,}
    return render(request, 'Entron/settings.html', context)

@permission_required('can_manage_settings')
def regenerate_registration_key(request):
    if request.method != "POST":
        return HttpResponse(status=405)
    company = _resolve_company_or_fallback(request)
    if company is None:
        return redirect('company_settings')
    prefix = secrets.token_hex(6)
    secret = secrets.token_hex(16)
    raw_key = f"{prefix}.{secret}"
    company.registration_key_prefix = prefix
    company.registration_key = make_password(raw_key)
    company.save()
    request.session['new_registration_key'] = raw_key
    messages.success(request, "Registration key regenerated. Copy it now -- it won't be shown again.")
    return redirect('company_settings')
@permission_required('can_manage_settings')
def change_company_password(request):
    if request.method != "POST":
        return HttpResponse(status=405)
    company = _resolve_company_or_fallback(request)
    if company is None:
        return redirect('company_settings')
    new_password = request.POST.get('new_password') or ''
    confirm_password = request.POST.get('confirm_password') or ''
    if len(new_password) < 8:
        messages.error(request, "Password must be at least 8 characters.")
        return redirect('company_settings')
    if new_password != confirm_password:
        messages.error(request, "Passwords don't match.")
        return redirect('company_settings')
    company.password = make_password(new_password)
    company.save()
    messages.success(request, "Company login password updated.")
    return redirect('company_settings')