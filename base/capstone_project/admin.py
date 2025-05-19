from django.contrib import admin
from .models import User, Council, Event, Analytics, Donation, Blockchain, Block

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['username', 'role', 'council', 'is_active', 'is_archived']
    list_filter = ['role', 'council', 'is_archived']
    search_fields = ['username', 'email']

@admin.register(Council)
class CouncilAdmin(admin.ModelAdmin):
    list_display = ['name', 'district']
    search_fields = ['name']

@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ['name', 'council', 'date']
    list_filter = ['council', 'date']
    search_fields = ['name']

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