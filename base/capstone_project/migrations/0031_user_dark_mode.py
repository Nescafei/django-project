# Generated migration for adding dark_mode field to User model

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('capstone_project', '0030_notification_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='dark_mode',
            field=models.BooleanField(default=False),
        ),
    ]
