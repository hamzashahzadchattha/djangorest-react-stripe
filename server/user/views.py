from django.contrib.auth import authenticate
from django.conf import settings
from django.middleware import csrf
from rest_framework import exceptions as rest_exceptions, response, decorators as rest_decorators, permissions as rest_permissions
from rest_framework_simplejwt import tokens, views as jwt_views, serializers as jwt_serializers, exceptions as jwt_exceptions
from user import serializers, models
import stripe
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

stripe.api_key = settings.STRIPE_SECRET_KEY
prices = {
    settings.WORLD_INDIVIDUAL: "world_individual",
    settings.WORLD_GROUP: "world_group",
    settings.WORLD_BUSINESS: "world_business",
    settings.UNIVERSE_INDIVIDUAL: "universe_individual",
    settings.UNIVERSE_GROUP: "universe_group",
    settings.UNIVERSE_BUSINESS: "universe_business"
}


def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {
        "refresh_token": str(refresh),
        "access_token": str(refresh.access_token)
    }


@swagger_auto_schema(
    method='post',  # Add this line
    operation_description="Login a user and return JWT tokens.",
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
        },
        required=['email', 'password']
    ),
    responses={
        200: openapi.Response('Successful login', openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'access_token': openapi.Schema(type=openapi.TYPE_STRING, description='JWT access token'),
                'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, description='JWT refresh token'),
            }
        )),
        400: "Bad request, validation error",
        401: "Authentication failed, incorrect email or password",
    },
    tags=['Authentication']
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([])
def loginView(request):
    serializer = serializers.LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data["email"]
    password = serializer.validated_data["password"]

    user = authenticate(email=email, password=password)

    if user is not None:
        tokens = get_user_tokens(user)
        res = response.Response()
        res.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=tokens["access_token"],
            expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )

        res.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
            value=tokens["refresh_token"],
            expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )

        res.data = tokens
        res["X-CSRFToken"] = csrf.get_token(request)
        return res
    raise rest_exceptions.AuthenticationFailed(
        "Email or Password is incorrect!")


@swagger_auto_schema(
    method='post',
    operation_description="Register a new user.",
    request_body=serializers.RegistrationSerializer,
    responses={
        200: "User registered successfully",
        400: "Bad request, validation error",
        401: "Authentication failed, invalid credentials",
    },
    tags=['Authentication']
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([])
def registerView(request):
    serializer = serializers.RegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.save()

    if user is not None:
        return response.Response("Registered!")
    return rest_exceptions.AuthenticationFailed("Invalid credentials!")


@swagger_auto_schema(
    method='post',
    operation_description="Logout the current user by blacklisting the refresh token and removing auth cookies.",
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            openapi.IN_HEADER,
            description="Bearer token containing the JWT access token",
            type=openapi.TYPE_STRING,
            required=True,
            default='Bearer ',
            examples={
                        'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            }
        ),
        openapi.Parameter(
            'X-CSRFToken',
            openapi.IN_HEADER,
            description="X-CSRFToken for protection against cross-site request forgery.",
            type=openapi.TYPE_STRING,
            required=True
        ),
        openapi.Parameter(
            'access',
            openapi.IN_HEADER,
            description="access (sent in cookies, but documented here for visibility: access=value)'",
            type=openapi.TYPE_STRING,
            required=True
        ),
        openapi.Parameter(
            'refresh',
            openapi.IN_HEADER,
            description="refresh (sent in cookies, but documented here for visibility: refresh=value)'",
            type=openapi.TYPE_STRING,
            required=True
        ),
        openapi.Parameter(
            'csrftoken',
            openapi.IN_HEADER,
            description="csrftoken (sent in cookies, but documented here for visibility: csrftoken=value)'",
            type=openapi.TYPE_STRING,
            required=True
        ),
    ],
    responses={
        200: "Logout successful. Access and refresh tokens have been invalidated.",
        400: "Bad request, invalid or missing tokens",
        401: "Unauthorized, authentication failed"
    },
    tags=['Authentication']
)
@rest_decorators.api_view(['POST'])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def logoutView(request):
    try:
        refreshToken = request.COOKIES.get(
            settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        token = tokens.RefreshToken(refreshToken)
        token.blacklist()

        res = response.Response()
        res.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
        res.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        res.delete_cookie("X-CSRFToken")
        res.delete_cookie("csrftoken")
        res["X-CSRFToken"] = None

        return res
    except:
        raise rest_exceptions.ParseError("Invalid token")


class CookieTokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = None

    def validate(self, attrs):
        attrs['refresh'] = self.context['request'].COOKIES.get('refresh')
        if attrs['refresh']:
            return super().validate(attrs)
        else:
            raise jwt_exceptions.InvalidToken(
                'No valid token found in cookie \'refresh\'')


class CookieTokenRefreshView(jwt_views.TokenRefreshView):
    serializer_class = CookieTokenRefreshSerializer

    @swagger_auto_schema(
        operation_description="Refresh the access token using the refresh token from the cookie.",
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Bearer token containing the JWT access token",
                type=openapi.TYPE_STRING,
                required=True,
                default='Bearer ',
                examples={
                    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                }
            ),
            openapi.Parameter(
                'X-CSRFToken',
                openapi.IN_HEADER,
                description="X-CSRFToken for protection against cross-site request forgery.",
                type=openapi.TYPE_STRING,
                required=True
            ),
            openapi.Parameter(
                'access',
                openapi.IN_HEADER,
                description="access (sent in cookies, but documented here for visibility: access=value)",
                type=openapi.TYPE_STRING,
                required=True
            ),
            openapi.Parameter(
                'refresh',
                openapi.IN_HEADER,
                description="refresh (sent in cookies, but documented here for visibility: refresh=value)",
                type=openapi.TYPE_STRING,
                required=True
            ),
            openapi.Parameter(
                'csrftoken',
                openapi.IN_HEADER,
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

    def finalize_response(self, request, response, *args, **kwargs):
        if response.data.get("refresh"):
            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                value=response.data['refresh'],
                expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
            )

            del response.data["refresh"]
        response["X-CSRFToken"] = request.COOKIES.get("csrftoken")
        return super().finalize_response(request, response, *args, **kwargs)


@swagger_auto_schema(
    method='get',
    operation_description="Get the authenticated user's information",
    manual_parameters=[
        openapi.Parameter(
            name='Authorization',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='Bearer token',
            examples={
                'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            }
        ),
        openapi.Parameter(
            name='csrftoken',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='CSRF token (sent in cookies, but documented here for visibility)'
        ),
        openapi.Parameter(
            name='access',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='access token (sent in cookies, but documented here for visibility)'
        ),
        openapi.Parameter(
            name='refresh',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='refresh token (sent in cookies, but documented here for visibility)'
        ),
        openapi.Parameter(
            'X-CSRFToken',
            openapi.IN_HEADER,
            description="CSRF token for protection against cross-site request forgery.",
            type=openapi.TYPE_STRING,
            required=True
        ),
    ],
    responses={
        200: openapi.Response(
            description="Successful response",
            schema=serializers.UserSerializer
        ),
        404: openapi.Response(
            description="User not found",
            examples={
                "application/json": {
                    "detail": "Not found."
                }
            }
        )
    },
    security=[
        {
            'bearerAuth': []
        }
    ],
    tags=['User']
)
@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def user(request):
    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status_code=404)

    serializer = serializers.UserSerializer(user)
    return response.Response(serializer.data)


@swagger_auto_schema(
    method='get',
    operation_description="Get active Stripe subscriptions for the authenticated user.",
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            openapi.IN_HEADER,
            description="Bearer token containing the JWT access token",
            type=openapi.TYPE_STRING,
            required=True,
            default='Bearer ',
            examples={
                'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            }
        ),
        openapi.Parameter(
            'X-CSRFToken',
            openapi.IN_HEADER,
            description="CSRF token for protection against cross-site request forgery.",
            type=openapi.TYPE_STRING,
            required=True
        ),
        openapi.Parameter(
            name='csrftoken',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='csrf token (sent in cookies, but documented here for visibility: csrftoken=value)'
        ),
        openapi.Parameter(
            name='access',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='access (sent in cookies, but documented here for visibility: access=value)'
        ),
        openapi.Parameter(
            name='refresh',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            required=True,
            description='refresh (sent in cookies, but documented here for visibility: refresh=value)'
        ),
    ],
    responses={
        200: openapi.Response('List of User active subscriptions', openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'subscriptions': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_STRING, description='Stripe subscription ID'),
                            'start_date': openapi.Schema(type=openapi.TYPE_STRING, description='Start date of the subscription (Unix timestamp)'),
                            'plan': openapi.Schema(type=openapi.TYPE_STRING, description='Name of the subscription plan'),
                        }
                    ),
                    description='List of active subscriptions'
                ),
            }
        )),
        404: "User not found",
        401: "Unauthorized, authentication failed or token expired",
    },
    security=[{'JWT': []}],
    tags=['Subscriptions']
)
@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def getSubscriptions(request):
    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status_code=404)

    subscriptions = []
    customer = stripe.Customer.search(query=f'email:"{user.email}"')
    if "data" in customer:
        if len(customer["data"]) > 0:
            for _customer in customer["data"]:
                subscription = stripe.Subscription.list(
                    customer=_customer["id"])
                if "data" in subscription:
                    if len(subscription["data"]) > 0:
                        for _subscription in subscription["data"]:
                            if _subscription["status"] == "active":
                                subscriptions.append({
                                    "id": _subscription["id"],
                                    "start_date": str(_subscription["start_date"]),
                                    "plan": prices[_subscription["plan"]["id"]]
                                })

    return response.Response({"subscriptions": subscriptions}, 200)
