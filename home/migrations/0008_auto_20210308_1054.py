# Generated by Django 3.1.7 on 2021-03-08 02:54

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0007_auto_20210308_1026'),
    ]

    operations = [
        migrations.RenameField(
            model_name='article',
            old_name='updateed',
            new_name='updated',
        ),
    ]
