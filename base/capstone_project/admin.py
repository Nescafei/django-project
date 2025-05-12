from django.contrib import admin
from .models import User, Council, Analytics

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'full_name', 'email', 'role', 'council', 'age', 'contact_number', 'current_degree', 'address', 'is_active', 'is_archived')
    list_filter = ('role', 'council', 'is_active', 'is_archived')
    search_fields = ('username', 'email', 'first_name', 'last_name')

    def full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}"
    full_name.short_description = 'Full Name'

@admin.register(Council)
class CouncilAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'district')
    search_fields = ('name', 'district')

@admin.register(Analytics)
class AnalyticsAdmin(admin.ModelAdmin):
    list_display = ('council', 'events_count', 'donations_amount', 'updated_by')
    list_filter = ('council',)
    search_fields = ('council__name',)