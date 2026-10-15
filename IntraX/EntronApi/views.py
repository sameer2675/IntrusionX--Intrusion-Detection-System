from django.shortcuts import render
from django.http import JsonResponse
import ipaddress
import json
import secrets
from datetime import timedelta
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import check_password, make_password
from Entron.models import  Device, Company, Alert, BlockAction
from django.db.models import Q
from django.utils.dateparse import parse_datetime
from django.utils import timezone
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address

# Create your views here.
ALERT_DEDUP_WINDOW_MINUTES = 60
BLOCK_COMMAND_TTL_MINUTES = 10
BLOCK_FAILURE_DEDUP_MINUTES = 15
BLOCK_EXPIRY_GRACE_SECONDS = 60
BLOCK_DEFAULT_DURATION_SECONDS = 900
ALERT_MAX_ACTIONS = 50


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


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = parse_datetime(value)
    except ValueError:
        return None
    if parsed is not None and timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.utc)
    return parsed


def _block_payload(action):
    return {
        "id": action.id,
        "device_id": str(action.device_id),
        "device_name": action.device.name,
        "alert_id": action.alert_id,
        "ip_address": action.ip_address,
        "cidr": action.cidr,
        "port": action.port,
        "status": action.status,
        "source": action.source,
        "attack_type": action.attack_type,
        "reason": action.reason,
        "message": action.message,
        "repeat_count": action.repeat_count,
        "unblock_requested": action.unblock_requested,
        "blocked_at": action.blocked_at.isoformat() if action.blocked_at else None,
        "expires_at": action.expires_at.isoformat() if action.expires_at else None,
        "created_at": action.created_at.isoformat(),
    }


def _broadcast_block(action):
    _broadcast(action.company_id, "block.update", {"block": _block_payload(action)})


def _record_agent_action(device, action_data, alert, attack_type, confidence):
    if not isinstance(action_data, dict):
        return None
    status = action_data.get('status')
    if status not in {"Blocked", "Failed"}:
        return None
    ip = action_data.get('ip')
    try:
        validate_ipv46_address(ip)
    except (TypeError, ValidationError):
        return None
    cidr = ""
    if action_data.get('cidr'):
        try:
            network = ipaddress.ip_network(str(action_data.get('cidr')), strict=False)
        except ValueError:
            return None
        if network.version != 4:
            return None
        cidr = str(network)
        ip = str(network.network_address)
    port = _to_int(action_data.get('port'))
    rule = str(action_data.get('rule') or "")[:100]
    reason = str(action_data.get('reason') or "")
    now = timezone.now()
    if status == "Blocked" and rule:
        existing = BlockAction.objects.filter(device=device, rule=rule, status="Blocked").first()
        if existing is not None:
            return existing
    if status == "Failed":
        recent_cutoff = now - timedelta(minutes=BLOCK_FAILURE_DEDUP_MINUTES)
        if BlockAction.objects.filter(device=device, ip_address=ip, status="Failed", created_at__gte=recent_cutoff).exists():
            return None
    repeat_count = _to_int(action_data.get('repeat_count'))
    if not repeat_count or repeat_count < 1:
        repeat_count = BlockAction.objects.filter(device=device, ip_address=ip).count() + 1
    action = BlockAction.objects.create(
        company=device.company,
        device=device,
        alert=alert,
        ip_address=ip,
        cidr=cidr,
        port=port,
        rule=rule,
        attack_type=attack_type,
        confidence=confidence,
        reason=reason if status == "Blocked" else "",
        message=reason if status == "Failed" else "",
        status=status,
        source="Auto",
        duration_seconds=_to_int(action_data.get('duration_seconds')) or BLOCK_DEFAULT_DURATION_SECONDS,
        repeat_count=repeat_count,
        blocked_at=_parse_time(action_data.get('blocked_at')),
        expires_at=_parse_time(action_data.get('expires_at')))
    _broadcast_block(action)
    return action


def _record_agent_actions(device, action_data, alert, attack_type, confidence, action_list=None):
    items = []
    if isinstance(action_data, dict):
        items.append(action_data)
    if isinstance(action_list, list):
        items.extend(item for item in action_list[:ALERT_MAX_ACTIONS] if isinstance(item, dict))
    recorded = None
    for item in items:
        result = _record_agent_action(device, item, alert, attack_type, confidence)
        if recorded is None:
            recorded = result
        if isinstance(item.get('range'), dict):
            _record_agent_action(device, item['range'], alert, attack_type, confidence)
    return recorded


def _pending_commands(device):
    now = timezone.now()
    stale_cutoff = now - timedelta(minutes=BLOCK_COMMAND_TTL_MINUTES)
    for action in BlockAction.objects.filter(device=device, status="Pending", created_at__lt=stale_cutoff):
        action.status = "Failed"
        action.message = "Agent did not respond in time."
        action.save()
        _broadcast_block(action)
    expiry_cutoff = now - timedelta(seconds=BLOCK_EXPIRY_GRACE_SECONDS)
    for action in BlockAction.objects.filter(device=device, status="Blocked", expires_at__lt=expiry_cutoff):
        action.status = "Expired"
        action.unblock_requested = False
        action.save()
        _broadcast_block(action)
    commands = []
    queued = BlockAction.objects.filter(device=device).filter(
        Q(status="Pending") | Q(status="Blocked", unblock_requested=True)).order_by('created_at')
    for action in queued:
        if action.status == "Pending":
            commands.append({
                "id": action.id,
                "type": "block",
                "ip": action.ip_address,
                "port": action.port,
                "protocol": action.protocol,
                "duration_seconds": action.duration_seconds,
                "reason": action.reason or action.attack_type or "Analyst block",
            })
        else:
            commands.append({
                "id": action.id,
                "type": "unblock",
                "ip": action.ip_address,
                "cidr": action.cidr or None,
                "port": action.port,
            })
    return commands


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
    if not hostname:
        return JsonResponse({'error': 'Missing required fields'}, status=400)
    try:
        validate_ipv46_address(ip_address or "0.0.0.0")
    except ValidationError:
        return JsonResponse({'error': 'Invalid IP address'}, status=400)

    raw_token = secrets.token_hex(16)
    device_fields = {
        'name': device_name,
        'cpu': cpu_info or "",
        'ram': ram_info or "",
        'os': operating_system or "",
        'architecture': architecture or "",
        'ip_address': ip_address or "0.0.0.0",
        'token': make_password(raw_token),
        'status': True,
    }
    device = Device.objects.filter(company=company, hostname=hostname).first()
    if device:
        for field, value in device_fields.items():
            setattr(device, field, value)
        device.save()
    else:
        device = Device.objects.create(company=company, hostname=hostname, **device_fields)

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
    except (Device.DoesNotExist, ValidationError, ValueError):
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
    device.security_status = data.get('security_status', device.security_status)
    device.flows_analyzed = data.get('flows_analyzed', device.flows_analyzed)
    device.attacks_detected = data.get('attacks_detected', device.attacks_detected)
    device.last_attack = data.get('last_attack', device.last_attack)
    device.last_confidence = data.get('last_confidence', device.last_confidence)
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
    "server_time": timezone.now().isoformat(),
    "commands": _pending_commands(device),
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
    if not attack_type or confidence is None or not source_ip or not destination_ip:
        return JsonResponse({'error': 'Missing required fields'}, status=400)
    try:
        confidence = float(confidence)
        validate_ipv46_address(source_ip)
        validate_ipv46_address(destination_ip)
    except (TypeError, ValueError, ValidationError):
        return JsonResponse({'error': 'Invalid confidence or IP address'}, status=400)
    protocol = str(protocol) if protocol is not None else ""
    if not isinstance(features, dict):
        features = {}
    recent_cutoff = timezone.now() - timedelta(minutes=ALERT_DEDUP_WINDOW_MINUTES)
    duplicate = (
        Alert.objects.filter(
            company=device.company,
            device=device,
            attack_type=attack_type,
            created_at__gte=recent_cutoff,)
        .order_by('-created_at')
        .first())
    action_data = data.get('action')
    action_list = data.get('actions')
    if duplicate is not None:
        _record_agent_actions(device, action_data, duplicate, attack_type, confidence, action_list)
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
        "description": alert.description,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "created_at": alert.created_at.isoformat(),}})
    _record_agent_actions(device, action_data, alert, attack_type, confidence, action_list)

    return JsonResponse({'success': True, 
                         'message': 'Alert received successfully',
                         'deduplicated': False,
                         'alert_id': str(alert.id)}, status=201)


@csrf_exempt
def actions(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    if not isinstance(data, dict):
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    token = data.get('token')
    device_id = data.get('device_id')
    results = data.get('results')
    if not token or not device_id or not isinstance(results, list):
        return JsonResponse({'error': 'Missing required fields'}, status=400)
    device = _authenticate_device(device_id, token)
    if device is None:
        return JsonResponse({'error': 'Invalid token or device ID'}, status=400)
    updated = 0
    for item in results:
        if not isinstance(item, dict):
            continue
        status = item.get('status')
        if status not in {"Blocked", "Failed", "Expired", "Unblocked"}:
            continue
        rule = str(item.get('rule') or "")[:100]
        action = None
        action_id = _to_int(item.get('id'))
        if action_id is not None:
            action = BlockAction.objects.filter(id=action_id, device=device).first()
        elif rule:
            action = BlockAction.objects.filter(device=device, rule=rule, status="Blocked").order_by('-created_at').first()
        if action is None:
            continue
        action.status = status
        action.message = str(item.get('message') or "")
        if rule:
            action.rule = rule
        blocked_at = _parse_time(item.get('blocked_at'))
        expires_at = _parse_time(item.get('expires_at'))
        if blocked_at is not None:
            action.blocked_at = blocked_at
        if expires_at is not None:
            action.expires_at = expires_at
        if status == "Blocked":
            repeat_count = _to_int(item.get('repeat_count'))
            if repeat_count and repeat_count > 0:
                action.repeat_count = repeat_count
        else:
            action.unblock_requested = False
        action.save()
        _broadcast_block(action)
        updated += 1
    return JsonResponse({'success': True, 'updated': updated}, status=200)