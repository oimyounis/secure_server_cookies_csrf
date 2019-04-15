import time

from django.conf import settings
from django.http.response import HttpResponse
from django.urls import resolve

from .decorators import excluded_funcs


class APISecurityMiddleware:
    """
    This middleware adds additional security to your API endpoints as it adds a custom header that holds hashed/encoded
    info that uses a special hashing/encoding function not known to anyone else.

    @property chars: These are the characters used in encoding, similar to a secret/key in other functions.
                    You have to have the same set of characters in the same order in your client-side code.
    @property exclude: An iterable holding all the urls that should not be checked for the header.
                        Always use Django's "reverse" function for added items.
    @property timespan: The seconds before the same request is invalidated when received again.
                        Protects you from "replay" attacks. Defaults to 6 seconds.
    """
    chars = ()
    timespan = 6
    exclude = ()

    def __init__(self, get_response):
        if hasattr(settings, 'API_MIDDLEWARE_CHARS'):
            APISecurityMiddleware.chars = settings.API_MIDDLEWARE_CHARS
        else:
            raise Exception('The API_MIDDLEWARE_CHARS setting is not defined!')

        if hasattr(settings, 'API_MIDDLEWARE_TIMESPAN'):
            APISecurityMiddleware.timespan = settings.API_MIDDLEWARE_TIMESPAN

        self.get_response = get_response

    def __call__(self, request):
        request_path = request.get_full_path()
        called_func = resolve(request.get_full_path()).func
        called_func_name = called_func.__name__ + '.' + request.method.lower()

        if request_path in APISecurityMiddleware.exclude or called_func_name in excluded_funcs:
            return self.get_response(request)

        try:
            req_id = request.META['HTTP_X_REQUEST_ID']
        except KeyError:
            return HttpResponse(status=401)

        pieces = req_id.split('+')
        url_last_segment = pieces[0]
        addr = pieces[1]
        timestamp = pieces[2]

        current_addr = request.META['REMOTE_ADDR']
        current_url_segments = request_path.split('/')
        current_url_last_segment = current_url_segments[-1]
        if not current_url_last_segment:
            current_url_last_segment = current_url_segments[-2]

        dehashed_segment = APISecurityMiddleware.dehash(url_last_segment)
        dehashed_addr = APISecurityMiddleware.dehash_int(addr)
        dehashed_time = int(APISecurityMiddleware.dehash_int(timestamp))

        if current_addr == dehashed_addr and current_url_last_segment == dehashed_segment and not self.time_expired(dehashed_time):
            return self.get_response(request)
        else:
            return HttpResponse(status=401)

    def time_expired(self, dehashed_time):
        return (int(time.time() / 0.001) - dehashed_time) / 1000 > int(APISecurityMiddleware.timespan)

    @classmethod
    def dehash_int(cls, int_string):
        dehashed = ''
        for char in int_string:
            if char == '?':
                dehashed += '.'
            else:
                dehashed += str(cls.chars.index(char))

        return dehashed

    @classmethod
    def dehash(cls, string):
        char_codes = []
        for idx, char in enumerate(string):
            is_of_three = idx % 3 == 0

            char_dehashed = APISecurityMiddleware.dehash_int(char)
            if is_of_three:
                char_codes.append(char_dehashed)
            else:
                char_codes[-1] += char_dehashed

        dehashed = ''.join(map(lambda code: chr(int(code)), char_codes))
        return dehashed
