# -*- coding: utf-8 -*-
# Generated by Django 1.11.12 on 2018-04-23 10:32
from __future__ import unicode_literals

import authentication_service.models
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentication_service', '0007_auto_20180423_0922'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='coreuser',
            index=authentication_service.models.TrigramIndex(fields=['username'], name='authenticat_usernam_ee0130_gin'),
        ),
        migrations.AddIndex(
            model_name='coreuser',
            index=authentication_service.models.TrigramIndex(fields=['email'], name='authenticat_email_84c43b_gin'),
        ),
        migrations.AddIndex(
            model_name='coreuser',
            index=authentication_service.models.TrigramIndex(fields=['first_name'], name='authenticat_first_n_9c2690_gin'),
        ),
        migrations.AddIndex(
            model_name='coreuser',
            index=authentication_service.models.TrigramIndex(fields=['last_name'], name='authenticat_last_na_40dea2_gin'),
        ),
    ]
