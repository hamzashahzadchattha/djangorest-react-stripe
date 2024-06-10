from django.contrib import admin
from django.urls import path, include

from drf_yasg import openapi
from drf_yasg.views import get_schema_view as swagger_get_schema_view

schema_view = swagger_get_schema_view(
    openapi.Info(
        title="Django Subscriptions API",
        default_version='v1',
        description="Subscriptions API",
    ),
    public=True,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('user.urls', namespace='user')),
    path('transaction/', include('transaction.urls', namespace='transaction')),
    path('', schema_view.with_ui('swagger', cache_timeout=0),
         name='schema-swagger-ui')
]
