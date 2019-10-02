from datetime import datetime

from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from rest_framework_jwt.settings import api_settings
from rest_framework import permissions
from rest_framework import status
from django.http.response import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie, requires_csrf_token
from django.utils.decorators import method_decorator
from rest_framework_jwt.serializers import RefreshJSONWebTokenSerializer

from .serializers import TokenSerializer
from secure_server.decorators import reqid_check_exempt

jwt_payload_default_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER


def jwt_payload_handler(user):
    payload = jwt_payload_default_handler(user)

    payload['customField'] = 'custom value'

    return payload


class JSONWebTokenAPIView(APIView):
    """
    Base API View that various JWT interactions inherit from.
    """
    permission_classes = ()
    authentication_classes = ()

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        return {
            'request': self.request,
            'view': self,
        }

    def get_serializer_class(self):
        """
        Return the class to use for the serializer.
        Defaults to using `self.serializer_class`.
        You may want to override this if you need to provide different
        serializations depending on the incoming request.
        (Eg. admins get full serialization, others get basic serialization)
        """
        assert self.serializer_class is not None, (
            "'%s' should either include a `serializer_class` attribute, "
            "or override the `get_serializer_class()` method."
            % self.__class__.__name__)
        return self.serializer_class

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """
        serializer_class = self.get_serializer_class()
        kwargs['context'] = self.get_serializer_context()
        return serializer_class(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user = serializer.object.get('user') or request.user
            token = serializer.object.get('token')
            # response_data = jwt_response_payload_handler(token, user, request)
            response_data = {}
            response = Response(response_data)
            if api_settings.JWT_AUTH_COOKIE:
                expiration = (datetime.utcnow() +
                              api_settings.JWT_REFRESH_EXPIRATION_DELTA)
                response.set_cookie(api_settings.JWT_AUTH_COOKIE,
                                    token,
                                    expires=expiration,
                                    httponly=False)
            return response

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RefreshJSONWebTokenAPI(JSONWebTokenAPIView):
    """
    API View that returns a refreshed token (with new expiration) based on
    existing token

    If 'orig_iat' field (original issued-at-time) is found, will first check
    if it's within expiration window, then copy it to the new token
    """
    serializer_class = RefreshJSONWebTokenSerializer


class LoginAPI(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        username = request.data.get("username", "").strip()
        password = request.data.get("password", "").strip()

        if not username or not password:
            return Response({'message': 'Enter valid username and password'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)

            serializer = TokenSerializer(data={
                # "token": jwt_encode_handler(
                #     jwt_payload_handler(user)
                # )
            })
            serializer.is_valid()
            res = Response(serializer.data)
            res.set_cookie(api_settings.JWT_AUTH_COOKIE, )
            if api_settings.JWT_AUTH_COOKIE:
                expiration = (datetime.utcnow() +
                              api_settings.JWT_REFRESH_EXPIRATION_DELTA)
                res.set_cookie(api_settings.JWT_AUTH_COOKIE,
                               jwt_encode_handler(jwt_payload_handler(user)),
                               expires=expiration,
                               httponly=False,
                               domain=settings.SESSION_COOKIE_DOMAIN, samesite='lax')
            return res
        else:
            return Response({'status': 0, 'message': 'Wrong username or password'}, status=400)


class AddrAPI(APIView):
    permission_classes = (permissions.AllowAny,)

    @method_decorator(ensure_csrf_cookie)
    def get(self, request, *args, **kwargs):
        return Response({'addr': request.META['REMOTE_ADDR']})


class RegisterAPI(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        username = request.data.get("username", "")
        password = request.data.get("password", "")
        email = request.data.get("email", "")
        if not username or not password or not email:
            return Response(
                data={
                    "message": "username, password and email are required to register a user"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        new_user = User.objects.create_user(
            username=username, password=password, email=email
        )

        return Response(status=status.HTTP_201_CREATED)


class UsersAPI(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        import time
        print('in UsersAPI', request.user.email, time.time())
        # time.sleep(3)
        return Response([
            {'name': 'user1', 'age': 25},
            {'name': 'user2', 'age': 15},
            {'name': 'user3', 'age': 18},
            {'name': 'user4', 'age': 19},
            {'name': 'user5', 'age': 11},
            {'name': 'user6', 'age': 31},
            {'name': 'user7', 'age': 47},
            {'name': 'user8', 'age': 18},
            {'name': 'user9', 'age': 59},
            {'name': 'user10', 'age': 10},
        ])
