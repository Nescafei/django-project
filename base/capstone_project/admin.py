from django.contrib import admin
from .models import User, Council, Event, Analytics, Donation, Blockchain, Block, ForumCategory, ForumMessage, Notification
from django.utils.html import format_html
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
# @admin.register(User)
# class UserAdmin(admin.ModelAdmin):
#     list_display = ['username', 'role', 'council', 'is_active', 'is_archived']
#     list_filter = ['role', 'council', 'is_archived']
#     search_fields = ['username', 'email']
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = (
        'username',
        'last_name',
        'first_name',
        'second_name',
        'middle_name',
        'middle_initial',
        'suffix',
        'email',
        'contact_number',
        'role',
        'council',
        'birthday',
        'gender',
        'religion',
        'get_full_address',
        'is_active',
    )
    list_filter = ('role', 'council', 'is_active', 'is_archived')
    search_fields = ('username', 'first_name', 'second_name', 'last_name', 'email')
    ordering = ('username',)

    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal Info', {
            'fields': (
                'first_name',
                'second_name',
                'middle_name',
                'middle_initial',
                'last_name',
                'suffix',
                'email',
                'street',
                'barangay',
                'city',
                'province',
                'contact_number',
                'birthday',
                'age',
                'gender',
                'religion',
                'profile_picture',
            )
        }),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Knights of Columbus Info', {
            'fields': ('role', 'council', 'current_degree', 'is_archived')
        }),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'username',
                'first_name',
                'second_name',
                'middle_name',
                'middle_initial',
                'last_name',
                'suffix',
                'email',
                'password1',
                'password2',
                'street',
                'barangay',
                'city',
                'province',
                'contact_number',
                'birthday',
                'gender',
                'religion',
                'role',
                'council',
            ),
        }),
    )

    @admin.display(description='Address')
    def get_full_address(self, obj):
        parts = [
            obj.street,
            obj.barangay,
            obj.city,
            obj.province,
        ]
        address = ', '.join(part for part in parts if part) or 'No address provided'
        return format_html(address)
    get_full_address.short_description = 'Address'


# @admin.register(Council)
# class CouncilAdmin(admin.ModelAdmin):
#     list_display = ['name', 'district']
#     search_fields = ['name']
@admin.register(Council)
class CouncilAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'district')
    search_fields = ('name', 'district')

# @admin.register(Event)
# class EventAdmin(admin.ModelAdmin):
#     list_display = ['name', 'council', 'date']
#     list_filter = ['council', 'date']
#     search_fields = ['name']
@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ('name', 'council', 'date_from', 'category', 'status', 'created_by', 'created_at')
    list_filter = ('council', 'date_from', 'category', 'status')
    search_fields = ('name', 'council__name', 'description')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Event Information', {
            'fields': ('name', 'description', 'category', 'council', 'status')
        }),
        ('Date Information', {
            'fields': ('date_from', 'date_until')
        }),
        ('Location', {
            'fields': ('street', 'barangay', 'city', 'province')
        }),
        ('Management Information', {
            'fields': ('created_by', 'approved_by', 'created_at', 'updated_at')
        }),
    )

@admin.register(Analytics)
class AnalyticsAdmin(admin.ModelAdmin):
    list_display = ['council', 'events_count', 'donations_amount', 'updated_by']
    list_filter = ['council']
    search_fields = ['council__name']

@admin.register(Blockchain)
class BlockchainAdmin(admin.ModelAdmin):
    list_display = ['id', 'pending_transactions_count']
    def pending_transactions_count(self, obj):
        return len(obj.pending_transactions)
    pending_transactions_count.short_description = 'Pending Transactions'

@admin.register(Block)
class BlockAdmin(admin.ModelAdmin):
    list_display = ['index', 'timestamp', 'transactions_count', 'proof', 'previous_hash', 'hash']
    list_filter = ['timestamp']
    search_fields = ['index']
    def transactions_count(self, obj):
        return len(obj.transactions)
    transactions_count.short_description = 'Transactions'

@admin.register(Donation)
class DonationAdmin(admin.ModelAdmin):
    list_display = [
        'transaction_id',
        'first_name',
        'last_name',
        'email',
        'amount',
        'donation_date',
        'payment_method',
        'status',
        'get_submitted_by',
        'get_reviewed_by',
    ]
    list_filter = ['status', 'payment_method', 'donation_date']
    search_fields = ['transaction_id', 'email', 'first_name', 'last_name']

    def get_submitted_by(self, obj):
        return obj.submitted_by.username if obj.submitted_by else 'None'
    get_submitted_by.short_description = 'Submitted By'

    def get_reviewed_by(self, obj):
        return obj.reviewed_by.username if obj.reviewed_by else 'None'
    get_reviewed_by.short_description = 'Reviewed By'

@admin.register(ForumCategory)
class ForumCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'description']
    search_fields = ['name', 'description']

@admin.register(ForumMessage)
class ForumMessageAdmin(admin.ModelAdmin):
    list_display = ['sender', 'category', 'timestamp', 'is_pinned', 'council', 'is_district_forum']
    list_filter = ['category', 'is_pinned', 'council', 'is_district_forum', 'timestamp']
    search_fields = ['content', 'sender__username']
    readonly_fields = ['timestamp']

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['user', 'message', 'is_read', 'timestamp']
    list_filter = ['is_read', 'timestamp']
    search_fields = ['user__username']
    readonly_fields = ['timestamp']