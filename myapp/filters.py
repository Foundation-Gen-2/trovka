# myapp/filters.py
import django_filters
from .models import Service

class ServiceFilter(django_filters.FilterSet):
    category = django_filters.CharFilter(field_name='category__category_name', lookup_expr='icontains')
    category_type = django_filters.CharFilter(field_name='category__category_type__name', lookup_expr='icontains')
    name = django_filters.CharFilter(field_name='name', lookup_expr='icontains')
    location = django_filters.CharFilter(field_name='location__province', lookup_expr='icontains')  # Example for filtering by location's province

    class Meta:
        model = Service
        fields = ['category', 'category_type', 'name', 'location']
