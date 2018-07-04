# -*- coding: utf-8 -*-
# Generated by Django 1.11.13 on 2018-07-04 06:33
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication_service', '0001_squashed_0011_auto_20180601_1241'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='OrganisationalUnit',
            new_name='Organisation',
        ),
        migrations.RenameField(
            model_name='coreuser',
            old_name='organisational_unit',
            new_name='organisation',
        ),
        migrations.AlterField(
            model_name='country',
            name='code',
            field=models.CharField(max_length=2, primary_key=True, serialize=False),
        ),
    ]
