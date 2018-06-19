import re
from urllib.parse import urlparse, parse_qs, urlencode
import logging

from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint
from oidc_provider.lib.errors import (
    AuthorizeError,
    ClientIdError,
    RedirectUriError
)

from django.conf import settings
from django.conf.urls.i18n import is_language_prefix_patterns_used
from django.http import HttpResponseBadRequest, HttpResponse
from django.middleware.locale import LocaleMiddleware
from django.shortcuts import render
from django.urls import reverse, reverse_lazy
from django.utils import translation
from django.utils.deprecation import MiddlewareMixin
from django.utils.translation import ugettext as _
from django.utils.translation.trans_real import language_code_prefix_re
from django.views.i18n import LANGUAGE_QUERY_PARAMETER

from authentication_service import exceptions, api_helpers
from authentication_service.constants import SessionKeys, EXTRA_SESSION_KEY
from authentication_service.utils import (
    update_session_data, get_session_data, delete_session_data
)


LOGGER = logging.getLogger(__name__)

# `set()` seems to force the evaluation of the callables returned by
# `reverse_lazy()`. This in turn causes issues with some comparisons, due to
# Django locales also playing a role in the url structures.
# TL;DR, keep this a list
SESSION_UPDATE_URL_WHITELIST = [
    reverse_lazy("registration"),
    reverse_lazy("oidc_provider:authorize"),
    reverse_lazy("edit_profile"),
]

def authorize_client(request):
    """
    Method to validate client values as supplied on request.

    Returns a oidc AuthorizeEndpoint object or a Django HttpResponse
    """
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

    return theme.lower() if isinstance(theme, str) else None


class ThemeManagementMiddleware(MiddlewareMixin):
    session_theme_key = SessionKeys.THEME

    def process_request(self, request):
        if request.path.rstrip("/") in [
                path.rstrip("/") for path in SESSION_UPDATE_URL_WHITELIST]:
            current_host = request.get_host()
            referer = request.META.get("HTTP_REFERER", None)
            parsed_referer = urlparse(referer)
            is_on_domain =  current_host == parsed_referer.netloc

            # Grab theme value off of url if available
            query_theme = fetch_theme(request, self.session_theme_key)
            if query_theme:
                update_session_data(
                    request, self.session_theme_key, query_theme
                )
            elif not is_on_domain:
                # Cleanup session values stored by this middleware
                delete_session_data(request, [self.session_theme_key])

        # Header still needs to be set PER request
        theme = get_session_data(request, self.session_theme_key)
        request.META["X-Django-Layer"] = theme


class SiteInactiveMiddleware(MiddlewareMixin):

    def process_request(self, request):
        # Before storing the redirect_uri, ensure it comes from a valid client.
        # This is to prevent urls on other parts of the site being misused to
        # redirect users to none client apps.

        # Should the site be disabled we need to prevent login. This helper function
        # checks if (1) this is a login request and (2) if the client_id provided is
        # linked to a disabled site. If so, login is prevented by rendering a custom
        # page explaining that the site has been disabled.
        if request.path.rstrip("/") == \
                reverse("oidc_provider:authorize").rstrip("/") and \
                request.method == "GET":
            authorize = authorize_client(request)
            if isinstance(authorize, HttpResponse):
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
    client_uri_key = SessionKeys.CLIENT_URI
    client_name_key = SessionKeys.CLIENT_NAME
    client_terms_key = SessionKeys.CLIENT_TERMS
    client_website = SessionKeys.CLIENT_WEBSITE
    client_id_key = SessionKeys.CLIENT_ID
    oidc_values = None


    def process_request(self, request):
        # Before storing the redirect_uri, ensure it comes from a valid client.
        # This is to prevent urls on other parts of the site being misused to
        # redirect users to none client apps.

        uri = request.GET.get("redirect_uri", None)
        client_id = request.GET.get("client_id", None)

        # The authorization of a client does a lookup every time it gets
        # called. Middleware, also fires off on each request. To guard against
        # unneeded db queries, we added an extra key unique to this middleware
        # that will not be effected if the redirect uri is changed elsewhere.
        validator_uri = get_session_data(request, "redirect_uri_validation")
        if request.path.rstrip("/") in [
                path.rstrip("/") for path in SESSION_UPDATE_URL_WHITELIST]:
            current_host = request.get_host()
            referer = request.META.get("HTTP_REFERER", None)
            parsed_referer = urlparse(referer)
            is_on_domain =  current_host == parsed_referer.netloc

            # Cleanup session values stored by this middleware
            if request.method == "GET" and not is_on_domain:
                delete_session_data(
                    request,
                    [
                        self.client_uri_key, self.client_name_key,
                        self.client_terms_key, "redirect_uri_validation",
                        self.client_id_key
                    ]
                )

            # Check whether it's an on domain redirect_uri
            if uri and not client_id:
                parsed_url = urlparse(uri)
                if parsed_url.netloc != "" and current_host != parsed_url.netloc:
                    raise exceptions.BadRequestException(
                        "client_id paramater is missing." \
                        " redirect_uri found that is not a" \
                        " relative path or on the authentication service domain."
                    )
            if uri and request.method == "GET" and uri != validator_uri and client_id:
                authorize = authorize_client(request)
                if isinstance(authorize, HttpResponse):
                    return authorize

                if isinstance(authorize, AuthorizeEndpoint):
                    update_session_data(
                        request,
                        self.client_name_key,
                        authorize.client.name
                    )
                    update_session_data(
                        request,
                        self.client_terms_key,
                        authorize.client.terms_url
                    )
                    update_session_data(
                        request,
                        self.client_website,
                        authorize.client.website_url
                    )
                    update_session_data(
                        request,
                        self.client_id_key,
                        authorize.client.id
                    )

            # Set uri if it got to this point
            if uri:
                update_session_data(
                    request,
                    self.client_uri_key,
                    uri
                )
                update_session_data(
                    request,
                    "redirect_uri_validation",
                    uri
                )


    def process_response(self, request, response):
        # Nice to have, extra cleanup hook
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


class GELocaleMiddleware(LocaleMiddleware):
    """
    Subclasses Django LocaleMiddleware

    Overrides the default logic to ALWAYS attempt to switch to the language
    provided via querystring.

    Most of this code was inspired by
    django.middleware.locales.LocaleMiddleware itself.
    """

    def process_request(self, request):
        super(GELocaleMiddleware, self).process_request(request)

        # Get the language code to use, can be a query
        language = {
            "code": request.GET.get(LANGUAGE_QUERY_PARAMETER, None),
            "type": "default"
        }

        # Need to cater for views with auth decorators that redirect to login
        next_query = request.GET.get("next")
        next_args = {}

        # Only attempt to get the langauge if there is a next query present
        if next_query:

            # Split on ?, seemingly the only way to get the full next url, in
            # the event the next is off domain .path will not suffice.
            parsed_query = urlparse(next_query)
            next_args = {
                "url": parsed_query.geturl().split("?", maxsplit=1)[0],
                "qs": parse_qs(parsed_query.query)
            }

            # Query values are in list form. Only grab the first value from the
            # list.
            language = {
                "code": next_args["qs"].get("language", [None])[0],
                "type": "next_query"
            }

        urlconf = getattr(request, "urlconf", settings.ROOT_URLCONF)

        # If the language can not be obtained from the path, there is no use in
        # appending the language and redirecting to it.
        language_from_path = translation.get_language_from_path(
            request.path_info
        )

        # Only if language code was provided, it is not the currently active
        # language, the url we are currently on does not already contain a
        # language code and the url does not contain the querystring language.
        if (language["code"] and
            language["code"] != translation.get_language() and
            language["code"] != language_from_path and
            language_from_path):

            # Make use of the locales regex that is traditionally used to
            # attempt to get the language from the url
            regex_match = language_code_prefix_re.match(request.get_full_path())

            # Ensure a language code is present, should not get here if not.
            # However check again for safety.
            if regex_match.group(1):

                # Replace the current language code in the full path with the
                # querystring one and redirect to it.
                path = request.path_info.replace(
                    regex_match.group(1),
                    language["code"],
                    1
                )

                # Remove the language parameter, can cause a infinite redirect
                # loop if the language is not found. Due to the base local
                # middleware also attempting redirects back to the default
                # language on 404s.
                get_query = request.GET.copy()
                if language["type"] == "default":
                    del get_query["language"]
                elif language["type"] == "next_query" and next_args:
                    next_args["qs"].pop("language")
                    get_query["next"] = next_args["url"] + f"?{urlencode(next_args['qs'])}"
                new_params = f"?{urlencode(get_query)}" if get_query else ""
                return self.response_redirect_class(f"{path}{new_params}")
