from django.views.generic.edit import CreateView, FormView
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model

from core_authentication_service import forms


class RegistrationView(CreateView):
    template_name = "core_authentication_service/registration.html"
    form_class = forms.RegistrationForm
    success_url = "/"

    def get_form_kwargs(self):
        kwargs = super(RegistrationView, self).get_form_kwargs()
        security = self.request.GET.get("security")
        if isinstance(security, str):
            kwargs["security"] = security.lower()
        return kwargs

    # TODO:
    #   - Add extra password validator for high security, in settings. upper, lower, digit and special check.
    #   - Handle required field querystring value.
    #   - Security question formset on registration.
    #   - Add 2FA to flow.
    #   - Handle theme querystring value, will need to effect 2FA templates as well.
    #   - Make it optional, but enforce able as required.
    #   - Will need to check client_id as provided for oidc login, for redirects not on domain. Validate client_id and redirect_uri before rendering form.
    #   - Add basis for invitation handling.
