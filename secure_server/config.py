import datetime
import os
from corsheaders.defaults import default_headers


# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '4+vgw065##&m(nheds2ij-h&6xl_c(v1*i(8^lpn*e-4vl!re2'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['192.168.2.93']

# Database
# https://docs.djangoproject.com/en/2.1/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

# JWT
JWT_EXPIRATION_DELTA = datetime.timedelta(minutes=5)
JWT_REFRESH_EXPIRATION_DELTA = datetime.timedelta(days=1)
JWT_ALLOW_REFRESH = True

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_jwt.authentication.JSONWebTokenAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.DjangoModelPermissionsOrAnonReadOnly'
    ],
    'DEFAULT_THROTTLE_CLASSES': (
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ),
    'DEFAULT_THROTTLE_RATES': {
        'anon': '60/minute',
        'user': '200/minute'
    },
}

CORS_ORIGIN_ALLOW_ALL = True

# CORS_ORIGIN_WHITELIST = (
#     'localhost:8080',
#     'localhost:8081',
#     'localhost:8082',
#     '192.168.2.93:8081',
# )

CORS_ALLOW_HEADERS = default_headers + (
    'X-REQUEST-ID',
)

API_MIDDLEWARE_CHARS = tuple('x4$59G!kW*')
API_MIDDLEWARE_TIMESPAN = 4

INTERNAL_IPS = ['127.0.0.1']
