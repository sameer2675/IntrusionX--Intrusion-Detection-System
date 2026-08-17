from django.shortcuts import render
from django.http import JsonResponse
import json
import secrets
from datetime import timedelta
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import check_password, make_password
from Entron.models import  Device, Company, Alert
from django.utils import timezone
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

# Create your views here.
ALERT_DEDUP_WINDOW_MINUTES = 60


def _broadcast(company_id, event_type, payload):
    try:
        channel_layer = get_channel_layer()
        if channel_layer is None:
            return
        async_to_sync(channel_layer.group_send)(
            f"company_{company_id}",
            {"type": event_type, **payload},)
    except Exception:
        pass


@csrf_exempt
def register_pc(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    registration_key = data.get('registration_key')
    device_name = data.get('device_name')
    hostname = data.get('hostname')
    cpu_info = data.get('cpu')
    operating_system = data.get('operating_system')
    architecture = data.get('architecture')
    ram_info = data.get('ram')
    ip_address = data.get('ip_address')
    if not registration_key or not device_name:
        return JsonResponse({'error': 'Missing required fields'}, status=400)
    company = None
    if '.' in registration_key:
        prefix, _, _ = registration_key.partition('.')
        candidate = Company.objects.filter(registration_key_prefix=prefix).first()
        if candidate and check_password(registration_key, candidate.registration_key):
            company = candidate

    if company is None:
        for candidate in Company.objects.filter(registration_key_prefix__isnull=True):
            if check_password(registration_key, candidate.registration_key):
                company = candidate
                break
    if company is None:
        return JsonResponse({'error': 'Invalid registration key'}, status=400)
    existing_device = Device.objects.filter(company=company, hostname=hostname).first()
    if existing_device:
        return JsonResponse({'error': 'Device with the same hostname already exists'}, status=400)

    raw_token = secrets.token_hex(16)
    device = Device.objects.create(
        company=company,
        name=device_name,
        hostname=hostname,
        cpu=cpu_info,
        ram=ram_info,
        os = operating_system,
        architecture = architecture,
        ip_address=ip_address,
        token=make_password(raw_token),
        status = True
    )

    _broadcast(company.id, "device.status", {"device": {
        "device_id": str(device.device_id),
        "name": device.name,
        "status": device.status,
        "cpu_usage": device.cpu_usage,
        "ram_usage": device.ram_usage,
        "disk_usage": device.disk_usage,
        "last_seen": device.last_seen.isoformat(),
        "security_status": device.security_status,
    }})

    return JsonResponse({'message': 'PC registered successfully',
     'token': raw_token,
     'device_id': str(device.device_id)}, status=201)


def _authenticate_device(device_id, token):
    try:
        device = Device.objects.get(device_id=device_id)
    except Device.DoesNotExist:
        return None
    if not token or not check_password(token, device.token):
        return None
    return device

@csrf_exempt
def heartbeat(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    token = data.get('token')
    device_id = data.get('device_id')
    ip_address = data.get('ip_address')
    cpu_usage = data.get('cpu_usage')
    ram_usage = data.get('ram_usage')
    disk_usage = data.get('disk_usage')
    if not token or not device_id:
        return JsonResponse({'error': 'Missing required fields'}, status=400)
    device = _authenticate_device(device_id, token)
    if device is None:
        return JsonResponse({'error': 'Invalid token or device ID'}, status=400)
    if ip_address:
        device.ip_address = ip_address
    if cpu_usage is not None:
        device.cpu_usage = cpu_usage
    if ram_usage is not None:
        device.ram_usage = ram_usage
    if disk_usage is not None:
        device.disk_usage = disk_usage
    device.last_seen = timezone.now()
    device.status = True 
    device.security_status = data.get('security_status', "Secure")
    device.flows_analyzed = data.get('flows_analyzed', 0)
    device.attacks_detected = data.get('attacks_detected', 0)
    device.last_attack = data.get('last_attack', device.last_attack)
    device.last_confidence = data.get('last_confidence', 0)
    device.save()

    _broadcast(device.company_id, "device.status", {"device": {
        "device_id": str(device.device_id),
        "name": device.name,
        "status": device.status,
        "cpu_usage": device.cpu_usage,
        "ram_usage": device.ram_usage,
        "disk_usage": device.disk_usage,
        "last_seen": device.last_seen.isoformat(),
        "security_status": device.security_status,}})

    return JsonResponse({'success': True, 
    'message': 'Heartbeat received successfully',
    "server_time": timezone.now().isoformat()
    }, status=200)

@csrf_exempt
def alert(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    device_id = data.get('device_id')
    token = data.get('token')
    attack_type = data.get('attack_type')
    confidence = data.get('confidence')
    source_ip = data.get('source_ip')
    destination_ip = data.get('destination_ip')
    protocol = data.get('protocol')
    features = data.get('features', {})

    valid_severities = {"Low", "Medium", "High"}
    severity = data.get('severity')
    if severity not in valid_severities:
        severity = "Medium"

    description = data.get('description') or f"{attack_type} detected from {source_ip} to {destination_ip}."

    if not device_id or not token:
        return JsonResponse({'error': 'Missing required fields'}, status=400)
    device = _authenticate_device(device_id, token)
    if device is None:
        return JsonResponse({'error': 'Invalid token or device ID'}, status=400)
    recent_cutoff = timezone.now() - timedelta(minutes=ALERT_DEDUP_WINDOW_MINUTES)
    duplicate = (
        Alert.objects.filter(
            company=device.company,
            device=device,
            attack_type=attack_type,
            created_at__gte=recent_cutoff,)
        .order_by('-created_at')
        .first())
    if duplicate is not None:
        return JsonResponse({
            'success': True,
            'message': 'Duplicate suppressed -- an alert for this attack type on this device is already active.',
            'deduplicated': True,
            'alert_id': str(duplicate.id),
        }, status=200)

    alert = Alert.objects.create(
        company=device.company,
        device=device,
        attack_type=attack_type,
        confidence=confidence,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        severity=severity,
        description=description,
        flow_features=features)
    _broadcast(device.company_id, "alert.new", {"alert": {
        "id": alert.id,
        "device_id": str(device.device_id),
        "device_name": device.name,
        "attack_type": alert.attack_type,
        "confidence": alert.confidence,
        "severity": alert.severity,
        "status": alert.status,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "created_at": alert.created_at.isoformat(),}})

    return JsonResponse({'success': True, 
                         'message': 'Alert received successfully',
                         'deduplicated': False,
                         'alert_id': str(alert.id)}, status=201)