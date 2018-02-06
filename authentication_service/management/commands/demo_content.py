# NOTE: Management command only to be used for setting up demo environments, do
# not use for anything else. Clients being set is bad enough, however the super
# user is created with an unsecure password that is visible in clear text in a
# public repo.

import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from oidc_provider.models import Client


class Command(BaseCommand):
    help = "Setup used for demonstration purposes only"

    def handle(self, *args, **options):
        c = Client(
            name="Wagtail client 1",
            client_id="client_id_1",
            client_secret="super_client_secret_1",
            response_type="code",
            jwt_alg="HS256",
            redirect_uris=[
                os.environ.get("WAGTAIL_1_IP",'http://example.com/')
            ]
        )
        c.save()

        c = Client(
            name="Wagtail client 2",
            client_id="client_id_2",
            client_secret="super_client_secret_2",
            response_type="code",
            jwt_alg="HS256",
            redirect_uris=[
                os.environ.get("WAGTAIL_2_IP",'http://example.com/')
            ]
        )
        c.save()

        # Super user
        user = get_user_model().objects.create(username="admin", is_superuser=1, is_staff=1)
        user.set_password("local")
        user.save()

        # End User
        end_user = get_user_model().objects.create(
            username="enduser", first_name="End", last_name="User"
        )
        end_user.set_password("enduser")
        end_user.save()
