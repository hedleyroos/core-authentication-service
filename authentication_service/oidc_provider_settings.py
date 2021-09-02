import datetime
import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.translation import ugettext as _

from oidc_provider.lib.claims import ScopeClaims

from authentication_service import api_helpers
from authentication_service.models import UserSite

USER_MODEL = get_user_model()

# Claims that map to None are known, but have no value we can set.
# Claims for which the resulting function returns None will be automatically
# omitted from the response.
CLAIMS_MAP = {
    "name": lambda user: "%s %s" % (user.first_name, user.last_name) \
        if user.first_name and user.last_name else None,
    "given_name": lambda user: user.first_name if user.first_name else None,
    "family_name": lambda user: user.last_name if user.last_name else None,
    "middle_name": None,
    "nickname": lambda user: user.nickname if user.nickname else user.username,
    "profile": lambda user: None,
    "preferred_username": lambda user: user.nickname or user.username,
    "picture": lambda user: user.avatar if user.avatar else None,
    "website": lambda user: None,
    "gender": lambda user: user.gender if user.gender else None,
    "birthdate": lambda user: user.birth_date if user.birth_date else None,
    "zoneinfo": lambda user: None,
    "locale": lambda user: user.country.code if
        user.country else None,
    "updated_at": lambda user: user.updated_at,
    "email": lambda user: user.email if user.email else None,
    "email_verified": lambda user: user.email_verified if
        user.email else None,
    "phone_number": lambda user: user.msisdn if user.msisdn else None,
    "phone_number_verified": lambda user: user.msisdn_verified if
        user.msisdn else None,
    "address": None,
}

LOGGER = logging.getLogger(__name__)


def userinfo(claims: dict, user: USER_MODEL) -> dict:
    """
    This function handles the standard claims defined for OpenID Connect.
    IMPORTANT: No keys may be removed or added to the claims dictionary.
    :param claims: A dictionary with claims as keys
    :param user: The user for which the information is claimed
    :return: The claims dictionary populated with values
    """
    LOGGER.debug("User info request for {}: Claims={}".format(user, claims))
    for key in claims:
        if key in CLAIMS_MAP:
            mapfun = CLAIMS_MAP[key]
            if mapfun:
                claims[key] = mapfun(user)
        else:
            LOGGER.error("Unsupported claim '{}' encountered.".format(key))

    return claims


class CustomScopeClaims(ScopeClaims):
    """
    A class facilitating custom scopes and claims. For more information, see
    http://django-oidc-provider.readthedocs.io/en/latest/sections/scopesclaims.html#how-to-add-custom-scopes-and-claims
    """

    # Update Basic profile description for GEINFRA-394
    info_profile = (
        _(u"Basic profile"),
        _(u"Access to your basic information. Includes names, gender,"
            " birthdate and other information."),
    )

    info_site = (
        _(u"Site"), _(u"Data for the requesting site"),
    )

    info_roles = (
        _(u"Roles"), _(u"Roles for the requesting site"),
    )

    def scope_site(self) -> dict:
        """
        The following attributes are available when constructing custom scopes:
        * self.user: The Django user instance.
        * self.userinfo: The dict returned by the OIDC_USERINFO function.
        * self.scopes: A list of scopes requested.
        * self.client: The Client requesting this claim.
        :return: A dictionary containing the claims for the custom Site scope
        """
        # Find the Site ID associated with this Client
        site_id = api_helpers.get_site_for_client(self.client.id)

        LOGGER.debug("Looking up site {} data for user {}".format(
            self.client.client_id, self.user))
        data = api_helpers.get_user_site_data(
            self.user.id, site_id).to_dict()["data"]
        now = timezone.now().astimezone(datetime.timezone.utc).isoformat()
        result = {
            "site": {"retrieved_at": f"{now}", "data": data},
        }
        if self.client.client_id == self.user.migration_data.get("client_id"):
            result["migration_information"] = self.user.migration_data

        return result

    def scope_roles(self) -> dict:
        """
        The following attributes are available when constructing custom scopes:
        * self.user: The Django user instance.
        * self.userinfo: The dict returned by the OIDC_USERINFO function.
        * self.scopes: A list of scopes requested.
        * self.client: The Client requesting this claim.
        :return: A dictionary containing the user roles as a list
        """
        LOGGER.debug("Requesting roles for user: %s/%s, on site: %s" % (
            self.user.username, self.user.id, self.client))

        roles = api_helpers.get_user_site_role_labels_aggregated(
            self.user.id, self.client.id)

        # Hedley modifications from here
        # The Access Control service doesn't currently have an API to query whether
        # a user has a certain permission on a resource, so we assemble a data structure
        # and let the client application do the access control check.
        role_ids = []
        role_id_labels = {}
        for role in api_helpers.get_role_list():
            if role.label in roles:
                role_ids.append(role.id)
            role_id_labels[role.id] = role.label

        # Map domain names for easy lookup
        domain_id_names = {}
        for domain in api_helpers.get_domain_list():
            domain_id_names[domain.id] = domain.name

        domain_access = {}
        for coded, role_ids in api_helpers.get_all_user_roles(str(self.user.id)).roles_map.items():
            if coded.startswith("d:"):
                dc, domain_id = coded.split(":")
                domain_id = int(domain_id)
                key = domain_id_names[domain_id]

                # Prep the structure
                domain_access[key] = {"roles": [], "resource_permissions": {}}

                # Set role labels
                for role_id in role_ids:
                    #domain_roles[key].append(role_id_labels[role_id])
                    domain_access[key]["roles"].append(role_id_labels[role_id])

                # Resource permissions for the domain
                final = {}
                resource_permissions = api_helpers.get_resource_permissions_for_roles(role_ids)
                resource_ids = []
                permission_ids = []
                for rp in resource_permissions:
                    resource_ids.append(rp.resource_id)
                    permission_ids.append(rp.permission_id)

                resource_urns = {}
                if resource_ids:
                    for resource in api_helpers.get_resource_list(resource_ids=resource_ids):
                        resource_urns[resource.id] = resource.urn

                permission_names = {}
                if permission_ids:
                    for permission in api_helpers.get_permission_list(permission_ids=permission_ids):
                        permission_names[permission.id] = permission.name

                for rp in resource_permissions:
                    resource_urn = resource_urns[rp.resource_id]
                    if resource_urn not in final:
                        final[resource_urn] = []
                    final[resource_urn].append(permission_names[rp.permission_id])

                domain_access[key]["resource_permissions"] = final

        result = {"roles": roles, "domain_access": domain_access}

        return result
