from django.urls import path

from . import views


app_name = "control"
urlpatterns = [
    path("docs/", views.swagger_docs, name="swagger-docs"),
    path("openapi.json", views.openapi_schema, name="openapi-schema"),
    path("healthz/", views.healthz, name="healthz"),
    path("api/v1/ip/", views.public_ipv4, name="public-ipv4"),
    path("api/v1/bootstrap/", views.bootstrap, name="bootstrap"),
    path("api/v1/proxy-jobs/", views.create_proxy_job, name="proxy-job-create"),
    path("api/v1/proxy-jobs/<int:job_id>/", views.proxy_job_detail, name="proxy-job-detail"),
    path("api/v1/profile-activity/", views.profile_activity, name="profile-activity"),
    path(
        "api/v1/proxies/<str:provider_code>/<str:country_code>/",
        views.proxy_file,
        name="proxy-file",
    ),
]
