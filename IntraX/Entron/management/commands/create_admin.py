from django.core.management.base import BaseCommand
from Entron.models import User
class Command(BaseCommand):
    help = "Create or reset the default staff login (admin / admin) used to register companies."
    def add_arguments(self, parser):
        parser.add_argument('--username', default='admin')
        parser.add_argument('--password', default='admin')
    def handle(self, *args, **options):
        username = options['username']
        password = options['password']
        user, created = User.objects.get_or_create(
            username=username,
            defaults={"email": f"{username}@local", "is_staff": True, "is_superuser": True},)
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        user.set_password(password)
        user.save()

        verb = "Created" if created else "Reset"
        self.stdout.write(self.style.SUCCESS(
            f"{verb} staff login -- username: '{username}', password: '{password}'"))
        self.stdout.write(self.style.WARNING(
            "This password is intentionally weak for local/dev onboarding use only -- "
            "change it before this ever faces the internet."))