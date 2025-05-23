# Generated by Django 5.2 on 2025-05-15 00:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('capstone_project', '0003_block_donation'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='block',
            options={},
        ),
        migrations.RemoveField(
            model_name='block',
            name='created_at',
        ),
        migrations.AlterField(
            model_name='block',
            name='hash',
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AlterField(
            model_name='block',
            name='index',
            field=models.IntegerField(default=1),
        ),
        migrations.AlterField(
            model_name='block',
            name='proof',
            field=models.BigIntegerField(),
        ),
        migrations.AlterField(
            model_name='block',
            name='transactions',
            field=models.JSONField(default=list),
        ),
    ]
