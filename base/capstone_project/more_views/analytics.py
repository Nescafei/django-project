from ..models import User, Council, Event, Analytics, Donation
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.views.decorators.cache import never_cache
from django.db.models import Sum, Avg, Q
from django.utils import timezone
import logging, json
import pandas as pd
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Min, Max, Avg, StdDev, Variance

logger = logging.getLogger(__name__)

@never_cache
@login_required
def analytics_view(request):
    if request.user.role not in ['admin', 'officer']:
        return redirect('dashboard')
    
    # Admin can select any council, officers are restricted to their own council
    if request.user.role == 'officer':
        council_id = str(request.user.council.id) if request.user.council else None
        councils = Council.objects.filter(id=council_id) if council_id else Council.objects.none()
    else:  # Admin
        council_id = request.GET.get('council_id')
        councils = Council.objects.all()

    # 1. Events Done Data
    events_qs = Event.objects.filter(status='approved')
    if council_id:
        events_qs = events_qs.filter(council_id=council_id)
    events_df = pd.DataFrame(list(events_qs.values('council__name')))
    if events_df.empty:
        council_name = Council.objects.get(id=council_id).name if council_id else 'Global'
        events_data = [{'council_name': council_name, 'count': 0}]
    else:
        events_df = events_df.groupby('council__name').size().reset_index(name='count')
        events_df['council_name'] = events_df['council__name'].fillna('Global')
        events_data = events_df.to_dict('records')
    logger.debug(f"Events data: {events_data}")

    # 2. Donations Per Month Data
    donations_qs = Donation.objects.filter(status='completed')
    if council_id:
        donations_qs = donations_qs.filter(submitted_by__council_id=council_id)
    donations_df = pd.DataFrame(list(donations_qs.values('donation_date', 'amount')))
    if donations_df.empty:
        donations_data = []
    else:
        donations_df['year'] = pd.to_datetime(donations_df['donation_date']).dt.year
        donations_df['month'] = pd.to_datetime(donations_df['donation_date']).dt.strftime('%B')  # Full month name (e.g., "May")
        donations_df = donations_df.groupby(['year', 'month'])['amount'].sum().reset_index()
        donations_df['month'] = donations_df['month']
        donations_data = [{'month': row['month'], 'total': float(row['amount'])} for _, row in donations_df.iterrows()]
    logger.debug(f"Donations data: {donations_data}")

    # 3. Members and Officers Data
    users_qs = User.objects.filter(is_archived=False)
    if council_id:
        users_qs = users_qs.filter(council_id=council_id)
    users_df = pd.DataFrame(list(users_qs.values('council__name', 'role')))
    if users_df.empty:
        council_name = Council.objects.get(id=council_id).name if council_id else 'Global'
        members_officers_data = [{'council_name': council_name, 'members': 0, 'officers': 0}]
    else:
        users_df['council_name'] = users_df['council__name'].fillna('Global')
        members_df = users_df[users_df['role'] == 'member'].groupby('council_name').size().reset_index(name='members')
        officers_df = users_df[users_df['role'] == 'officer'].groupby('council_name').size().reset_index(name='officers')
        merged_df = pd.merge(members_df, officers_df, on='council_name', how='outer').fillna(0)
        members_officers_data = merged_df.to_dict('records')
    logger.debug(f"Members/officers data: {members_officers_data}")

    # 4. Event Type Distribution
    # Valid event categories from add_event.html
    valid_categories = ['Exemplification', 'Service Program', 'Council Meeting', 'Assembly Meeting']
    
    event_types_qs = Event.objects.filter(status='approved', category__in=valid_categories)
    if council_id:
        event_types_qs = event_types_qs.filter(council_id=council_id)
    event_types_df = pd.DataFrame(list(event_types_qs.values('category')))
    if event_types_df.empty:
        event_types_data = []
    else:
        event_types_df = event_types_df.groupby('category').size().reset_index(name='count')
        event_types_data = event_types_df.to_dict('records')
    logger.debug(f"Event types data: {event_types_data}")

    # 5. Donation Source Breakdown
    donation_sources_qs = Donation.objects.filter(status='completed')
    if council_id:
        donation_sources_qs = donation_sources_qs.filter(submitted_by__council_id=council_id)
    donation_sources_df = pd.DataFrame(list(donation_sources_qs.values('payment_method', 'amount')))
    if donation_sources_df.empty:
        donation_sources_data = []
    else:
        donation_sources_df = donation_sources_df.groupby('payment_method')['amount'].sum().reset_index()
        donation_sources_data = [{'payment_method': row['payment_method'], 'amount': float(row['amount'])} for _, row in donation_sources_df.iterrows()]
    logger.debug(f"Donation sources data: {donation_sources_data}")

    # 6. Active vs. Inactive Members
    # Active = members with activity in last 30 days (recruitment or event attendance)
    # Inactive = members with no activity in last 30 days
    from datetime import timedelta
    
    users_qs = User.objects.filter(is_archived=False, role='member')
    if council_id:
        users_qs = users_qs.filter(council_id=council_id)
    
    thirty_days_ago = timezone.now().date() - timedelta(days=30)
    
    # Count active members (recently joined OR had recent activity)
    active_members = users_qs.filter(
        Q(date_joined__date__gte=thirty_days_ago) |  # Newly joined within 30 days
        Q(recruitments__date_recruited__gte=thirty_days_ago) |  # Recent recruitment
        Q(event_attendances__is_present=True, event_attendances__event__date_from__gte=thirty_days_ago)  # Recent attendance
    ).distinct().count()
    
    # Count inactive members (no recent activity and joined more than 30 days ago)
    inactive_members = users_qs.exclude(
        Q(date_joined__date__gte=thirty_days_ago) |
        Q(recruitments__date_recruited__gte=thirty_days_ago) |
        Q(event_attendances__is_present=True, event_attendances__event__date_from__gte=thirty_days_ago)
    ).count()
    
    logger.debug(f"Active members: {active_members}, Inactive members: {inactive_members}")
    member_activity_data = [
        {'category': 'Active Members', 'count': active_members},
        {'category': 'Inactive Members', 'count': inactive_members}
    ]
    logger.debug(f"Member activity data: {member_activity_data}")

    # 7. Summary Statistics
    summary_stats = {
        'total_events': float(Event.objects.filter(status='approved').count() if not council_id else Event.objects.filter(status='approved', council_id=council_id).count()),
        'total_donations': float(Donation.objects.filter(status='completed').aggregate(Sum('amount'))['amount__sum'] or 0) if not council_id else float(Donation.objects.filter(status='completed', submitted_by__council_id=council_id).aggregate(Sum('amount'))['amount__sum'] or 0),
        'total_members': float(User.objects.filter(is_archived=False, role='member').count() if not council_id else User.objects.filter(is_archived=False, role='member', council_id=council_id).count()),
        'total_officers': float(User.objects.filter(is_archived=False, role='officer').count() if not council_id else User.objects.filter(is_archived=False, role='officer', council_id=council_id).count()),
        'avg_donation': float(Donation.objects.filter(status='completed').aggregate(Avg('amount'))['amount__avg'] or 0) if not council_id else float(Donation.objects.filter(status='completed', submitted_by__council_id=council_id).aggregate(Avg('amount'))['amount__avg'] or 0),
    }
    logger.debug(f"Summary stats: {summary_stats}")

    # === FIGURE 15: Descriptive Statistics (Central Tendency + Dispersion) ===

    descriptive_stats = {}

    # 1. Donations Amount (per completed donation)
    donations_for_stats = Donation.objects.filter(status='completed')
    if council_id:
        donations_for_stats = donations_for_stats.filter(submitted_by__council_id=council_id)

    donation_amounts = donations_for_stats.values_list('amount', flat=True)
    if donation_amounts:
        import statistics
        amounts_list = list(donation_amounts)
        descriptive_stats['donations'] = {
            'count': len(amounts_list),
            'mean': round(statistics.mean(amounts_list), 2),
            'median': statistics.median(amounts_list),
            'mode': statistics.mode(amounts_list) if len(set(amounts_list)) > 1 else amounts_list[0],
            'std_dev': round(statistics.stdev(amounts_list) if len(amounts_list) > 1 else 0, 2),
            'min': min(amounts_list),
            'max': max(amounts_list),
        }
    else:
        descriptive_stats['donations'] = {'count': 0, 'mean': 0, 'median': 0, 'mode': 0, 'std_dev': 0, 'min': 0, 'max': 0}

    # 2. Events per Council (only if NO council filter → shows variation across councils)
    if not council_id:
        events_per_council = Event.objects.filter(status='approved')\
            .values('council_id')\
            .annotate(count=Count('id'))\
            .values_list('count', flat=True)
        counts = list(events_per_council)
        descriptive_stats['events_per_council'] = {
            'count': len(counts),
            'mean': round(statistics.mean(counts), 2) if counts else 0,
            'median': statistics.median(counts) if counts else 0,
            'mode': statistics.mode(counts) if counts and len(set(counts)) > 1 else (counts[0] if counts else 0),
            'std_dev': round(statistics.stdev(counts) if len(counts) > 1 else 0, 2),
            'min': min(counts) if counts else 0,
            'max': max(counts) if counts else 0,
        }
    else:
        # When filtered, just show total events (no variation)
        total_events = Event.objects.filter(status='approved', council_id=council_id).count()
        descriptive_stats['events_per_council'] = {
            'count': 1,
            'mean': total_events,
            'median': total_events,
            'mode': total_events,
            'std_dev': 0,
            'min': total_events,
            'max': total_events,
        }

    # 3. Active Member Ratio (%)
    total_members = User.objects.filter(is_archived=False, role='member')
    if council_id:
        total_members = total_members.filter(council_id=council_id)
    total_members_count = total_members.count()

    active_members_count = total_members.filter(
        Q(submitted_donations__status='completed') |
        Q(event_attendances__is_present=True, event_attendances__event__status='approved')
    ).distinct().count()

    ratio = (active_members_count / total_members_count * 100) if total_members_count > 0 else 0

    descriptive_stats['active_member_ratio'] = {
        'percentage': round(ratio, 2),
        'active_count': active_members_count,
        'total_count': total_members_count
    }


    # Convert data to JSON for Chart.js
    context = {
        'councils': councils,
        'selected_council': council_id,
        'events_data': json.dumps(events_data),
        'donations_data': json.dumps(donations_data),
        'members_officers_data': json.dumps(members_officers_data),
        'event_types_data': json.dumps(event_types_data),
        'donation_sources_data': json.dumps(donation_sources_data),
        'member_activity_data': json.dumps(member_activity_data),
        'summary_stats': summary_stats,
        'is_officer': request.user.role == 'officer',
        'descriptive_stats': descriptive_stats,
    }
    return render(request, 'analytics_view.html', context)

@never_cache
@login_required
def analytics_form(request):
    if request.user.role != 'officer':
        return redirect('dashboard')
    council = request.user.council
    if request.method == 'POST':
        events_count = int(request.POST.get('events_count', 0))
        donations_amount = float(request.POST.get('donations_amount', 0.00))
        analytics, created = Analytics.objects.get_or_create(council=council)
        analytics.events_count = events_count
        analytics.donations_amount = donations_amount
        analytics.updated_by = request.user
        analytics.save()
        return redirect('dashboard')
    analytics = Analytics.objects.filter(council=council).first()
    return render(request, 'analytics_form.html', {'analytics': analytics})
