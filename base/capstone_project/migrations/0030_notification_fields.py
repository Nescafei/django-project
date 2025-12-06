# Generated migration for notification system enhancements

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('capstone_project', '0029_donation_is_anonymous'),
    ]

    operations = [
        migrations.AddField(
            model_name='notification',
            name='notification_type',
            field=models.CharField(
                choices=[
                    ('pending_proposal', 'Pending Proposal/Member'),
                    ('donation_received', 'Donation Received'),
                    ('event_today', 'Event Happening Today'),
                    ('donation_quota_reached', 'Donation Quota Reached'),
                    ('proposal_accepted', 'Proposal Accepted'),
                    ('proposal_rejected', 'Proposal Rejected'),
                    ('pending_member_approval', 'Pending Member Approval'),
                    ('officer_inactive', 'Officer Inactive'),
                    ('council_moved', 'Moved to New Council'),
                    ('promoted_to_officer', 'Promoted to Officer'),
                    ('demoted_to_member', 'Demoted to Member'),
                    ('recruiter_assigned', 'Assigned as Recruiter'),
                    ('event_attended', 'Event Attended'),
                    ('member_inactive', 'Member Inactive'),
                    ('member_moved', 'Moved to New Council'),
                    ('member_promoted', 'Promoted to Officer'),
                    ('member_demoted', 'Demoted to Member'),
                    ('member_recruiter', 'Assigned as Recruiter'),
                    ('member_attended', 'Event Attended'),
                    ('forum_message', 'Forum Message'),
                ],
                default='forum_message',
                max_length=50,
            ),
        ),
        migrations.AddField(
            model_name='notification',
            name='related_council',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='notifications',
                to='capstone_project.council',
            ),
        ),
        migrations.AddField(
            model_name='notification',
            name='related_event',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='notifications',
                to='capstone_project.event',
            ),
        ),
        migrations.AddField(
            model_name='notification',
            name='related_user',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='notifications_about_user',
                to='capstone_project.user',
            ),
        ),
    ]
