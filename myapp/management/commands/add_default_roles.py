from django.core.management.base import BaseCommand
from myapp.models import Role

class Command(BaseCommand):
    help = 'Initialize roles in the database'

    def handle(self, *args, **kwargs):
        roles = ['user', 'provider', 'admin']
        for role_name in roles:
            if not Role.objects.filter(role_name=role_name).exists():
                Role.objects.create(role_name=role_name)
                self.stdout.write(self.style.SUCCESS(f'Successfully created role: {role_name}'))
            else:
                self.stdout.write(self.style.WARNING(f'Role already exists: {role_name}'))
