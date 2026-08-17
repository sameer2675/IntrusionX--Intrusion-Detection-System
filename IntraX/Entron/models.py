from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid

class Company(models.Model):
    id = models.UUIDField(primary_key = True, default = uuid.uuid4, editable = False)
    name = models.CharField(max_length = 100)
    username = models.CharField(max_length = 100, unique=True)
    email = models.CharField(max_length = 100)
    registration_key = models.CharField(max_length = 100, unique=True)
    registration_key_prefix = models.CharField(max_length=16, unique=True, null=True, blank=True, db_index=True)
    password = models.CharField(max_length = 128, blank = True, default = '')
    created_at = models.DateTimeField(auto_now_add = True)
    def __str__(self):
        return self.name
class User(AbstractUser):
    company = models.ForeignKey(Company, on_delete = models.CASCADE, null = True, blank = True)
    email = models.EmailField(max_length=100, unique=True)
    is_active = models.BooleanField(default = True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    can_manage_alerts = models.BooleanField(default=True)
    can_manage_devices = models.BooleanField(default=True)
    can_add_admins = models.BooleanField(default=False)
    can_manage_settings = models.BooleanField(default=False)
    def __str__(self):
        return self.username
class Device(models.Model):
    device_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    token = models.CharField(max_length=100, unique=True, blank=True, null=True)
    agent_version = models.CharField(max_length=50, default="1.0.0")
    company = models.ForeignKey(Company, on_delete = models.CASCADE, null=True, blank=True)
    cpu = models.CharField(max_length=100)
    os = models.CharField(max_length=100)
    architecture = models.CharField(max_length=100)
    ram = models.CharField(max_length=100)
    cpu_usage = models.FloatField(default=0.0)
    ram_usage = models.FloatField(default=0.0)
    disk_usage = models.FloatField(default=0.0)
    ip_address = models.GenericIPAddressField()
    hostname = models.CharField(max_length=100)
    last_seen = models.DateTimeField(auto_now=True)
    status = models.BooleanField(default=True)
    security_status = models.CharField(max_length=50,default="Secure")
    flows_analyzed = models.IntegerField(default=0)
    attacks_detected = models.IntegerField(default=0)
    last_attack = models.CharField(max_length=100,blank=True,null=True)
    last_confidence = models.FloatField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.name


class Alert(models.Model):

    STATUS = [
        ("Pending", "Pending"),
        ("Resolved", "Resolved"),
    ]

    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, null=True, blank=True)
    attack_type = models.CharField(max_length=100)
    confidence = models.FloatField()
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    protocol = models.CharField(max_length=50)
    severity = models.CharField(max_length=20,choices=[("Low", "Low"), ("Medium", "Medium"),("High", "High"),],default="Medium")
    status = models.CharField(max_length=20, choices=STATUS, default="Pending")
    flow_features = models.JSONField(default=dict)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.attack_type