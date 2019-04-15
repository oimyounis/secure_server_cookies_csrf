from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from rest_framework_jwt.settings import api_settings
from rest_framework import permissions
from rest_framework import status

from .serializers import TokenSerializer
from secure_server.decorators import reqid_check_exempt

jwt_payload_default_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER


def jwt_payload_handler(user):
    payload = jwt_payload_default_handler(user)

    payload['customField'] = 'custom value'

    return payload


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
                "token": jwt_encode_handler(
                    jwt_payload_handler(user)
                )})
            serializer.is_valid()
            return Response(serializer.data)
        else:
            return Response({'status': 0, 'message': 'Wrong username or password'}, status=400)


class AddrAPI(APIView):
    permission_classes = (permissions.AllowAny,)

    @reqid_check_exempt
    def get(self, request, *args, **kwargs):
        return Response({'addr': request.META['REMOTE_ADDR']})


# Add custom API here

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

    def get(self, request):
        import time
        time.sleep(3)
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
