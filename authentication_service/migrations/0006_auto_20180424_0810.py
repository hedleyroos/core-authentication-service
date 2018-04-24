# -*- coding: utf-8 -*-
# Generated by Django 1.11.12 on 2018-04-24 08:10
from __future__ import unicode_literals

import authentication_service.models
from django.db import migrations, models
import django.db.models.deletion
import partial_index


class Migration(migrations.Migration):

    dependencies = [
        ('authentication_service', '0005_auto_20180307_1212'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='coreuser',
            options={},
        ),
        migrations.AddField(
            model_name='coreuser',
            name='q',
            field=authentication_service.models.AutoQueryField(default=''),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='coreuser',
            name='country',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='authentication_service.Country', verbose_name='country'),
        ),
        migrations.AlterField(
            model_name='coreuser',
            name='gender',
            field=models.CharField(blank=True, choices=[('female', 'Female'), ('male', 'Male'), ('other', 'Other')], max_length=10, null=True, verbose_name='gender'),
        ),
        migrations.AlterField(
            model_name='usersecurityquestion',
            name='answer',
            field=models.TextField(verbose_name='answer'),
        ),
        migrations.AddIndex(
            model_name='coreuser',
            index=models.Index(fields=['date_joined'], name='authenticat_date_jo_188bff_idx'),
        ),
        migrations.AddIndex(
            model_name='coreuser',
            index=models.Index(fields=['gender'], name='authenticat_gender_277866_idx'),
        ),
        migrations.AddIndex(
            model_name='coreuser',
            index=models.Index(fields=['last_login'], name='authenticat_last_lo_f8ef1c_idx'),
        ),
        migrations.AddIndex(
            model_name='coreuser',
            index=models.Index(fields=['updated_at'], name='authenticat_updated_766884_idx'),
        ),
        migrations.AddIndex(
            model_name='coreuser',
            index=partial_index.PartialIndex(fields=['is_active'], name='authenticat_is_acti_7ff3d3_partial', unique=False, where='', where_postgresql='is_active = false', where_sqlite=''),
        ),
        migrations.AddIndex(
            model_name='coreuser',
            index=partial_index.PartialIndex(fields=['email_verified'], name='authenticat_email_v_74d3e8_partial', unique=False, where='', where_postgresql='email_verified = true', where_sqlite=''),
        ),
        migrations.AddIndex(
            model_name='coreuser',
            index=partial_index.PartialIndex(fields=['msisdn_verified'], name='authenticat_msisdn__e2202e_partial', unique=False, where='', where_postgresql='msisdn_verified = true', where_sqlite=''),
        ),
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
        migrations.AddIndex(
            model_name='coreuser',
            index=authentication_service.models.TrigramIndex(fields=['q'], name='authenticat_q_2fcb4b_gin'),
        ),
    ]
