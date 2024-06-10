# Django and React Authentication with JWT and Stripe payment

The project consists of two directories: 

- `client`: Contains the React application
- `server`: Contains the Django backend

## Installation

To run this project on your local machine, follow the steps below:

### Prerequisites

Ensure you have the following installed on your local machine:

- Python 3.8 or higher
- Node.js v14.15.0 or higher
- npm 6.14.9 or higher

### Setup

1. Clone the repository:
    ```
    git clone https://github.com/<yourusername>/<yourrepository>.git
    ```
2. Change into the directory:
    ```
    cd <yourrepository>
    ```

### Server

1. Navigate to the `server` directory:
    ```
    cd server
    ```
2. Install Django and other dependencies:
    ```
    pip install -r requirements.txt
    ```
3. Create a virtual environment (Optional but recommended):
    ```
    python -m venv env
    ```
4. Activate the virtual environment:
    On Windows:
    ```
    .\env\Scripts\activate
    ```
    On MacOS/Linux:
    ```
    source env/bin/activate
    ```
5. Create a `.env` file in the `server/core` directory and add stripe secret key and prices (copy from .env.example)

### Client

1. Navigate to the `client` directory:
    ```
    cd ../client
    ```
2. Install all the dependencies:
    ```
    npm install
    ```
3. Create `index.js` in `client/src/config` directory and add stripe key and prices (copy from index.js.example)
4. Run the client:
    ```
    npm start
    ```

Now, your application should be running at `localhost:3000`.

Note:
- The Django server should be running at the same time as the React application for the system to function properly.
- The application uses the email field instead of the username field for user identification.


# Task
- Clone this project to your local and Run this project successfully
- Review how the frontend and stripe subscriptions are working
- Add Swagger or Redoc API documentation for Django restful API endpoints (Write down well-organized and well-documented API reference)
- Create a new repository to your personal git and commit the result.

# Django REST Project Documentation

## Swagger Documentation Using `drf_yasg`

To provide a comprehensive and interactive API documentation, this project uses `drf_yasg`. Below is the process to set up and use `drf_yasg` for generating Swagger documentation.

### Setup `drf_yasg`

1. Install `drf_yasg`:
    ```
    pip install drf-yasg
    ```
2. Update settings.py: Add drf_yasg to your INSTALLED_APPS
    ```
    INSTALLED_APPS = [
        ...
        'drf_yasg',
        ...
    ]
    ```
3. Configure URL Patterns: In your urls.py, add the following configurations to include the Swagger UI 
    ```
    from rest_framework import permissions
    from drf_yasg.views import get_schema_view
    from drf_yasg import openapi

    schema_view = swagger_get_schema_view(
    openapi.Info(
        title="Django Subscriptions API",
        default_version='v1',
        description="Subscriptions API",
    ),
    public=True,
    )

    urlpatterns = [
        ...
        path('/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
        ...
    ]
    ```
4. Annotate Views: Use @swagger_auto_schema decorator to annotate your views for better documentation. Here is an example for a token refresh view:
    ```
    from drf_yasg.utils import swagger_auto_schema
    from drf_yasg import openapi

    class CookieTokenRefreshView(jwt_views.TokenRefreshView):
        serializer_class = CookieTokenRefreshSerializer

        @swagger_auto_schema(
            operation_description="Refresh the access token using the refresh token from the cookie.",
            manual_parameters=[
                openapi.Parameter(
                    'Authorization', openapi.IN_HEADER,
                    description="Bearer token containing the JWT access token",
                    type=openapi.TYPE_STRING,
                    required=True,
                    default='Bearer ',
                    examples={'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'}
                ),
                openapi.Parameter(
                    'X-CSRFToken', openapi.IN_HEADER,
                    description="X-CSRFToken for protection against cross-site request forgery.",
                    type=openapi.TYPE_STRING,
                    required=True
                ),
                openapi.Parameter(
                    'access', openapi.IN_HEADER,
                    description="access (sent in cookies, but documented here for visibility: access=value)",
                    type=openapi.TYPE_STRING,
                    required=True
                ),
                openapi.Parameter(
                    'refresh', openapi.IN_HEADER,
                    description="refresh (sent in cookies, but documented here for visibility: refresh=value)",
                    type=openapi.TYPE_STRING,
                    required=True
                ),
                openapi.Parameter(
                    'csrftoken', openapi.IN_HEADER,
                    description="csrftoken (sent in cookies, but documented here for visibility: csrftoken=value)",
                    type=openapi.TYPE_STRING,
                    required=True
                ),
            ],
            responses={
                200: openapi.Response('New tokens', openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'access': openapi.Schema(type=openapi.TYPE_STRING, description='New JWT access token'),
                    }
                )),
                401: openapi.Response(description="Invalid or missing refresh token"),
            },
            tags=['Authentication']
        )
        def post(self, request, *args, **kwargs):
            return super().post(request, *args, **kwargs)
    ```




## Below is POSTMAN Api collection and Environmental Variables For This Project.
 
### API Collection
  https://api.postman.com/collections/35060703-ebd9206f-b491-45ad-918e-5487ee9cc76b?access_key=PMAT-01J0157EFM9C31BTKYQFXDS1N3

### Environment


    {
	"id": "ea9da2ad-f7fe-4455-899c-e92c6c4b7641",
	"name": "django_subscription_app_env_local",
	"values": [
		{
			"key": "Base_URL",
			"value": "http://127.0.0.1:8000",
			"type": "default",
			"enabled": true
		},
		{
			"key": "AccessToekn",
			"value": "",
			"type": "default",
			"enabled": true
		},
		{
			"key": "RefreshToken",
			"value": "",
			"type": "default",
			"enabled": true
		},
		{
			"key": "CsrfToken",
			"value": "",
			"type": "default",
			"enabled": true
		},
		{
			"key": "X-CSRFToken",
			"value": "",
			"type": "default",
			"enabled": true
		}
	],
	"_postman_variable_scope": "environment",
	"_postman_exported_at": "2024-06-10T13:27:01.780Z",
	"_postman_exported_using": "Postman/11.1.25"
    }

