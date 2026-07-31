from django.urls import path

from . import views


app_name = "control"
urlpatterns = [
    path("docs/", views.swagger_docs, name="swagger-docs"),
    path("openapi.json", views.openapi_schema, name="openapi-schema"),
    path("healthz/", views.healthz, name="healthz"),
    path("api/v1/ip/", views.public_ipv4, name="public-ipv4"),
    path("api/v1/bootstrap/", views.bootstrap, name="bootstrap"),
    path(
        "api/v1/proxies/<str:provider_code>/<str:country_code>/",
        views.proxy_file,
        name="proxy-file",
    ),
]
