"""core_authentication_service URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin

from two_factor.urls import urlpatterns as two_factor_patterns

from core_authentication_service import views


urlpatterns = [
    url(r"^admin/", admin.site.urls),
    url(r"^openid/", include("oidc_provider.urls", namespace="oidc_provider")),
    url(r"^two-factor-auth", include(two_factor_patterns, namespace="two_factor_auth")),
    # Registration URLs
    url(
        r"^registration/$",
        views.RegistrationView.as_view(),
        name="registration"
    ),
]
