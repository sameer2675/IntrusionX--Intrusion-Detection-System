from django.contrib import admin
from .models import Company, User, Device, Alert
# Register your models here.
admin.site.register(Company)
admin.site.register(User)
admin.site.register(Device)
admin.site.register(Alert)