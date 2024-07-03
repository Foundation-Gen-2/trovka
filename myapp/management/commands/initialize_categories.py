from django.core.management.base import BaseCommand
from myapp.models import CategoryType, Category

class Command(BaseCommand):
    help = 'Initialize category types and categories'

    def handle(self, *args, **kwargs):
        categories = {
            'Restaurants': ['Juice Bar', 'Khmer Food', 'Cafe'],
            'Home services': ['Electricians', 'Contractors', 'Plumbers', 'Janitor', 'HVAC'],
            'Auto services': ['Auto Repair', 'Car Wash', 'Car Dealers'],
            'Electronics': ['Phone Repair', 'Computer Repair', 'TV and Audio Repair', 'Camera Repair'],
        }

        for category_type_name, subcategories in categories.items():
            category_type, created = CategoryType.objects.get_or_create(name=category_type_name)
            for subcategory_name in subcategories:
                Category.objects.get_or_create(
                    category_name=subcategory_name,
                    category_type=category_type
                )

        self.stdout.write(self.style.SUCCESS('Successfully initialized categories and subcategories'))
