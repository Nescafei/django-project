from django.db import migrations

def create_initial_categories(apps, schema_editor):
    ForumCategory = apps.get_model('capstone_project', 'ForumCategory')
    categories = [
        ('general', 'General discussion'),
        ('event_proposals', 'Event proposals and planning'),
        ('announcements', 'Important announcements'),
        ('feedback', 'Feedback and suggestions'),
        ('questions', 'Questions and help'),
        ('urgent', 'Urgent matters'),
    ]
    
    for name, description in categories:
        ForumCategory.objects.create(name=name, description=description)

class Migration(migrations.Migration):
    dependencies = [
        ('capstone_project', '0013_forumcategory_alter_event_options_and_more'),
    ]

    operations = [
        migrations.RunPython(create_initial_categories),
    ] 