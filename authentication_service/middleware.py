from urllib.parse import urlparse, parse_qs
import logging

from django.urls import reverse, reverse_lazy
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint
from oidc_provider.lib.errors import (
    AuthorizeError,
    ClientIdError,
    RedirectUriError
)

from django.shortcuts import render
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseBadRequest
from django.utils.translation import ugettext as _

from authentication_service import exceptions, api_helpers
from authentication_service.constants import SESSION_KEYS, EXTRA_SESSION_KEY
from authentication_service.utils import (
    update_session_data, get_session_data, delete_session_data
)


LOGGER = logging.getLogger(__name__)

# TODO make use of whitelist
SESSION_UPDATE_URL_WHITELIST = [
    reverse_lazy("registration"),
    reverse_lazy("oidc_provider:authorize"),
    reverse_lazy("edit_profile"),
]


def fetch_theme(request, key=None):
    # Set get theme from either request or session. Request always wins to
    # ensure stale theme is not used.
    theme = request.GET.get("theme")

    # In the event no theme has been found, try to check if theme is present in
    # a next query. This is to cater for the event where Django auth middleware
    # needed to redirect to login. Auth middleware redirects on the request
    # already.
    if theme is None:
        next_query = request.GET.get("next")

        # Only attempt to get the theme if there is a next query present, this
        # is the only known edge case we have to cater for.
        if next_query:
            next_query_args = parse_qs(urlparse(next_query).query)

            # Query values are in list form. Only grab the first value from the
            # list.
            theme = next_query_args.get("theme", [None])[0]

    if theme is None:
        theme = get_session_data(request, key)

    return theme.lower() if isinstance(theme, str) else theme


class ThemeManagementMiddleware(MiddlewareMixin):
    session_theme_key = SESSION_KEYS["theme"]

    def process_request(self, request):
        theme = fetch_theme(request, self.session_theme_key)
        if request.path in SESSION_UPDATE_URL_WHITELIST:
            if theme:
                update_session_data(request, self.session_theme_key, theme)
            else:
               delete_session_data(request, self.session_theme_key)

        # Header still needs to be set PER request
        request.META["X-Django-Layer"] = theme


def authorize_client(request):
    authorize = AuthorizeEndpoint(request)
    try:
        authorize.validate_params()
    except (ClientIdError, RedirectUriError) as e:
        return render(
            request,
            "authentication_service/redirect_middleware_error.html",
            {"error": e.error, "message": e.description},
            status=500
        )
    except AuthorizeError as e:
        # Suppress one of the errors oidc raises. It is not required
        # for pages beyond login.
        if e.error == "unsupported_response_type":
            pass
        else:
            raise e
    return authorize


class SiteInactiveMiddleware(MiddlewareMixin):

    def process_request(self, request):
        # Before storing the redirect_uri, ensure it comes from a valid client.
        # This is to prevent urls on other parts of the site being misused to
        # redirect users to none client apps.

        # Should the site be disabled we need to prevent login. This helper function
        # checks if (1) this is a login request and (2) if the client_id provided is
        # linked to a disabled site. If so, login is prevented by rendering a custom
        # page explaining that the site has been disabled.
        path_without_trailing_slash = request.path.rstrip("/")
        if path_without_trailing_slash == reverse("oidc_provider:authorize") and \
                request.method != "POST":
            authorize = authorize_client(request)
            if not isinstance(authorize, AuthorizeEndpoint):
                return authorize
            site_is_active = api_helpers.is_site_active(authorize.client)
            if not site_is_active:
                return render(
                    request,
                    "authentication_service/redirect_middleware_error.html",
                    {
                        "error": _("Site access disabled"),
                        "message": _("The site you are trying to log in to has been disabled.")
                    },
                    status=403
                )


class SessionDataManagementMiddleware(MiddlewareMixin):
    """
    NOTE: This Middleware should always be as near the end of the Middleware
    list in settings. Middleware is evaluated in order and this needs to happen
    as near the end as possible.
    """
    client_uri_key = SESSION_KEYS["redirect_client_uri"]
    client_name_key = SESSION_KEYS["redirect_client_name"]
    client_terms_key = SESSION_KEYS["redirect_client_terms"]
    oidc_values = None


    def process_request(self, request):
        # Before storing the redirect_uri, ensure it comes from a valid client.
        # This is to prevent urls on other parts of the site being misused to
        # redirect users to none client apps.

        uri = request.GET.get("redirect_uri", None)

        # The authorization of a client does a lookup every time it gets
        # called. Middleware, also fires off on each request. To guard against
        # unneeded db queries, we added an extra key unique to this middleware
        # that will not be effected if the redirect uri is changed elsewhere.
        validator_uri = get_session_data(request, "redirect_uri_validation")
        if uri and request.method != "POST" and uri != validator_uri:
            authorize = authorize_client(request)
            if not isinstance(authorize, AuthorizeEndpoint):
                return authorize

            if isinstance(authorize, AuthorizeEndpoint):
                update_session_data(
                    request,
                    self.client_name_key,
                    authorize.client.name
                )
                update_session_data(
                    request,
                    self.client_uri_key,
                    authorize.params["redirect_uri"]
                )
                update_session_data(
                    request,
                    self.client_terms_key,
                    authorize.client.terms_url
                )
                update_session_data(
                    request,
                    "redirect_uri_validation",
                    uri
                )

    def process_response(self, request, response):
        if response.status_code == 302:
            current_host = request.get_host()
            location = response.get("Location", "")
            parsed_url = urlparse(location)
            if parsed_url.netloc != "" and current_host != parsed_url.netloc:
                LOGGER.warning(
                    "User redirected off domain; " \
                    "(%s) -> (%s)." % (
                        current_host, parsed_url.netloc
                    )
                )
                # Clear all extra session data
                request.session.pop(EXTRA_SESSION_KEY, None)

        return response


class ErrorMiddleware(MiddlewareMixin):
    def process_exception(self, request, exc):
        if isinstance(exc, exceptions.BadRequestException):
            return HttpResponseBadRequest(exc.args)
