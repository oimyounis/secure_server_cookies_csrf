import time
import re
import string
import random
import hashlib
from urllib.parse import urlparse
import hmac
from django.utils.encoding import force_bytes

from django.conf import settings
from django.http.response import HttpResponse
from django.urls import resolve
from django.core.exceptions import DisallowedHost, ImproperlyConfigured
from django.utils.cache import patch_vary_headers
from django.urls import get_callable
from django.utils.http import is_same_domain

from .decorators import excluded_funcs


from django.middleware.csrf import CsrfViewMiddleware
from rest_framework import exceptions


REASON_NO_REFERER = "Referer checking failed - no Referer."
REASON_BAD_REFERER = "Referer checking failed - %s does not match any trusted origins."
REASON_NO_CSRF_COOKIE = "CSRF cookie not set."
REASON_BAD_TOKEN = "CSRF token missing or incorrect."
REASON_MALFORMED_REFERER = "Referer checking failed - Referer is malformed."
REASON_INSECURE_REFERER = "Referer checking failed - Referer is insecure while host is secure."

CSRF_SECRET_LENGTH = 32
CSRF_TOKEN_LENGTH = 2 * CSRF_SECRET_LENGTH
CSRF_ALLOWED_CHARS = string.ascii_letters + string.digits
CSRF_SESSION_KEY = '_csrftoken'


def _get_failure_view():
    """Return the view to be used for CSRF rejections."""
    return get_callable(settings.CSRF_FAILURE_VIEW)


try:
    random = random.SystemRandom()
    using_sysrandom = True
except NotImplementedError:
    import warnings
    warnings.warn('A secure pseudo-random number generator is not available '
                  'on your system. Falling back to Mersenne Twister.')
    using_sysrandom = False


class CSRFCheck(CsrfViewMiddleware):
    def _reject(self, request, reason):
        # Return the failure reason instead of an HttpResponse
        return reason


def get_random_string(length=12,
                      allowed_chars='abcdefghijklmnopqrstuvwxyz'
                                    'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
    """
    Return a securely generated random string.

    The default length of 12 with the a-z, A-Z, 0-9 character set returns
    a 71-bit value. log_2((26+26+10)^12) =~ 71 bits
    """
    if not using_sysrandom:
        # This is ugly, and a hack, but it makes things better than
        # the alternative of predictability. This re-seeds the PRNG
        # using a value that is hard for an attacker to predict, every
        # time a random string is required. This may change the
        # properties of the chosen random sequence slightly, but this
        # is better than absolute predictability.
        random.seed(
            hashlib.sha256(
                ('%s%s%s' % (random.getstate(), time.time(), settings.SECRET_KEY)).encode()
            ).digest()
        )
    return ''.join(random.choice(allowed_chars) for i in range(length))


def _get_failure_view():
    print('Return the view to be used for CSRF rejections', settings.CSRF_FAILURE_VIEW)
    # return get_callable(settings.CSRF_FAILURE_VIEW)
    return None


def _get_new_csrf_string():
    return get_random_string(CSRF_SECRET_LENGTH, allowed_chars=CSRF_ALLOWED_CHARS)


def _salt_cipher_secret(secret):
    """
    Given a secret (assumed to be a string of CSRF_ALLOWED_CHARS), generate a
    token by adding a salt and using it to encrypt the secret.
    """
    salt = _get_new_csrf_string()
    chars = CSRF_ALLOWED_CHARS
    pairs = zip((chars.index(x) for x in secret), (chars.index(x) for x in salt))
    cipher = ''.join(chars[(x + y) % len(chars)] for x, y in pairs)
    return salt + cipher


def _unsalt_cipher_token(token):
    """
    Given a token (assumed to be a string of CSRF_ALLOWED_CHARS, of length
    CSRF_TOKEN_LENGTH, and that its first half is a salt), use it to decrypt
    the second half to produce the original secret.
    """
    salt = token[:CSRF_SECRET_LENGTH]
    token = token[CSRF_SECRET_LENGTH:]
    chars = CSRF_ALLOWED_CHARS
    pairs = zip((chars.index(x) for x in token), (chars.index(x) for x in salt))
    secret = ''.join(chars[x - y] for x, y in pairs)  # Note negative values are ok
    return secret


def _get_new_csrf_token():
    return _salt_cipher_secret(_get_new_csrf_string())


def _sanitize_token(token):
    # Allow only ASCII alphanumerics
    if re.search('[^a-zA-Z0-9]', token):
        return _get_new_csrf_token()
    elif len(token) == CSRF_TOKEN_LENGTH:
        return token
    elif len(token) == CSRF_SECRET_LENGTH:
        # Older Django versions set cookies to values of CSRF_SECRET_LENGTH
        # alphanumeric characters. For backwards compatibility, accept
        # such values as unsalted secrets.
        # It's easier to salt here and be consistent later, rather than add
        # different code paths in the checks, although that might be a tad more
        # efficient.
        return _salt_cipher_secret(token)
    return _get_new_csrf_token()


def constant_time_compare(val1, val2):
    """Return True if the two strings are equal, False otherwise."""
    return hmac.compare_digest(force_bytes(val1), force_bytes(val2))


def _compare_salted_tokens(request_csrf_token, csrf_token):
    # Assume both arguments are sanitized -- that is, strings of
    # length CSRF_TOKEN_LENGTH, all CSRF_ALLOWED_CHARS.
    return constant_time_compare(
        _unsalt_cipher_token(request_csrf_token),
        _unsalt_cipher_token(csrf_token),
    )


def get_token(request):
    """
    Return the CSRF token required for a POST form. The token is an
    alphanumeric value. A new token is created if one is not already set.

    A side effect of calling this function is to make the csrf_protect
    decorator and the CsrfViewMiddleware add a CSRF cookie and a 'Vary: Cookie'
    header to the outgoing response.  For this reason, you may need to use this
    function lazily, as is done by the csrf context processor.
    """
    if "CSRF_COOKIE" not in request.META:
        csrf_secret = _get_new_csrf_string()
        request.META["CSRF_COOKIE"] = _salt_cipher_secret(csrf_secret)
    else:
        csrf_secret = _unsalt_cipher_token(request.META["CSRF_COOKIE"])
    request.META["CSRF_COOKIE_USED"] = True
    return _salt_cipher_secret(csrf_secret)


class CSRFCheckMiddleware(CsrfViewMiddleware):
    def __init__(self, get_response=None):
        super(CSRFCheckMiddleware, self).__init__(get_response)
        self.get_reponse = get_response

    def __call__(self, request):
        if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
            return self.get_reponse(request)
        if self.authenticate(request):
            return self.process_response(request, self.get_reponse(request))
        else:
            return HttpResponse('csrftoken check failed', status=403)

    def authenticate(self, request):
        """
        Returns a `User` if the request session currently has a logged in user.
        Otherwise returns `None`.
        """

        # Get the session-based user from the underlying HttpRequest object
        # user = getattr(request, 'user', None)

        # Unauthenticated, CSRF validation not required
        # if not user or not user.is_active:
        #     return None

        self.enforce_csrf(request)

        # CSRF passed with authenticated user
        return True

    def _get_token(self, request):
        if settings.CSRF_USE_SESSIONS:
            try:
                return request.session.get(CSRF_SESSION_KEY)
            except AttributeError:
                raise ImproperlyConfigured(
                    'CSRF_USE_SESSIONS is enabled, but request.session is not '
                    'set. SessionMiddleware must appear before CsrfViewMiddleware '
                    'in MIDDLEWARE%s.' % ('_CLASSES' if settings.MIDDLEWARE is None else '')
                )
        else:
            try:
                cookie_token = request.COOKIES[settings.CSRF_COOKIE_NAME]
            except KeyError:
                return None

            csrf_token = _sanitize_token(cookie_token)

            if csrf_token != cookie_token:
                # Cookie token needed to be replaced;
                # the cookie needs to be reset.
                request.csrf_cookie_needs_reset = True
            return csrf_token

    def enforce_csrf(self, request):
        """
        Enforce CSRF validation for session based authentication.
        """
        # check = CSRFCheck()
        # populates request.META['CSRF_COOKIE'], which is used in process_view()

        csrf_token = self._get_token(request)

        if csrf_token is not None:
            # Use same token next time.
            request.META['CSRF_COOKIE'] = csrf_token

        reason = self.process_view(request, None, (), {})
        if reason:
            # CSRF failed, bail with explicit error message
            raise exceptions.PermissionDenied('exceptions.PermissionDenied: CSRF Failed: %s' % reason)

    def _accept(self, request):
        # Avoid checking the request twice by adding a custom attribute to
        # request.  This will be relevant when both decorator and middleware
        # are used.
        request.csrf_processing_done = True
        request.META["CSRF_COOKIE_USED"] = True

        return None

    def _reject(self, request, reason):
        # response = _get_failure_view()(request, reason=reason)
        # print('Forbidden (%s): %s' % (reason, request.path))
        return 'Forbidden (%s): %s' % (reason, request.path)

    def process_view(self, request, callback, callback_args, callback_kwargs):
        if getattr(request, 'csrf_processing_done', False):
            return None

        # Wait until request.META["CSRF_COOKIE"] has been manipulated before
        # bailing out, so that get_token still works
        if getattr(callback, 'csrf_exempt', False):
            return None

        # Assume that anything not defined as 'safe' by RFC7231 needs protection
        if request.method not in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
            if getattr(request, '_dont_enforce_csrf_checks', False):
                # Mechanism to turn off CSRF checks for test suite.
                # It comes after the creation of CSRF cookies, so that
                # everything else continues to work exactly the same
                # (e.g. cookies are sent, etc.), but before any
                # branches that call reject().
                return self._accept(request)

            if request.is_secure():
                # Suppose user visits http://example.com/
                # An active network attacker (man-in-the-middle, MITM) sends a
                # POST form that targets https://example.com/detonate-bomb/ and
                # submits it via JavaScript.
                #
                # The attacker will need to provide a CSRF cookie and token, but
                # that's no problem for a MITM and the session-independent
                # secret we're using. So the MITM can circumvent the CSRF
                # protection. This is true for any HTTP connection, but anyone
                # using HTTPS expects better! For this reason, for
                # https://example.com/ we need additional protection that treats
                # http://example.com/ as completely untrusted. Under HTTPS,
                # Barth et al. found that the Referer header is missing for
                # same-domain requests in only about 0.2% of cases or less, so
                # we can use strict Referer checking.
                referer = request.META.get('HTTP_REFERER')
                if referer is None:
                    return self._reject(request, REASON_NO_REFERER)

                referer = urlparse(referer)

                # Make sure we have a valid URL for Referer.
                if '' in (referer.scheme, referer.netloc):
                    return self._reject(request, REASON_MALFORMED_REFERER)

                # Ensure that our Referer is also secure.
                if referer.scheme != 'https':
                    return self._reject(request, REASON_INSECURE_REFERER)

                # If there isn't a CSRF_COOKIE_DOMAIN, require an exact match
                # match on host:port. If not, obey the cookie rules (or those
                # for the session cookie, if CSRF_USE_SESSIONS).
                good_referer = (
                    settings.SESSION_COOKIE_DOMAIN
                    if settings.CSRF_USE_SESSIONS
                    else settings.CSRF_COOKIE_DOMAIN
                )
                if good_referer is not None:
                    server_port = request.get_port()
                    if server_port not in ('443', '80'):
                        good_referer = '%s:%s' % (good_referer, server_port)
                else:
                    try:
                        # request.get_host() includes the port.
                        good_referer = request.get_host()
                    except DisallowedHost:
                        pass

                # Create a list of all acceptable HTTP referers, including the
                # current host if it's permitted by ALLOWED_HOSTS.
                good_hosts = list(settings.CSRF_TRUSTED_ORIGINS)
                if good_referer is not None:
                    good_hosts.append(good_referer)

                if not any(is_same_domain(referer.netloc, host) for host in good_hosts):
                    reason = REASON_BAD_REFERER % referer.geturl()
                    return self._reject(request, reason)

            csrf_token = request.META.get('CSRF_COOKIE')
            if csrf_token is None:
                # No CSRF cookie. For POST requests, we insist on a CSRF cookie,
                # and in this way we can avoid all CSRF attacks, including login
                # CSRF.
                return self._reject(request, REASON_NO_CSRF_COOKIE)

            # Check non-cookie token for match.
            request_csrf_token = ""
            if request.method == "POST":
                try:
                    request_csrf_token = request.POST.get('csrfmiddlewaretoken', '')
                except IOError:
                    # Handle a broken connection before we've completed reading
                    # the POST data. process_view shouldn't raise any
                    # exceptions, so we'll ignore and serve the user a 403
                    # (assuming they're still listening, which they probably
                    # aren't because of the error).
                    pass

            if request_csrf_token == "":
                # Fall back to X-CSRFToken, to make things easier for AJAX,
                # and possible for PUT/DELETE.
                request_csrf_token = request.META.get(settings.CSRF_HEADER_NAME, '')

            request_csrf_token = _sanitize_token(request_csrf_token)
            if not _compare_salted_tokens(request_csrf_token, csrf_token):
                return self._reject(request, REASON_BAD_TOKEN)

        return self._accept(request)

    def _set_token(self, request, response):
        if settings.CSRF_USE_SESSIONS:
            request.session[CSRF_SESSION_KEY] = request.META['CSRF_COOKIE']
        else:
            response.set_cookie(
                settings.CSRF_COOKIE_NAME,
                request.META['CSRF_COOKIE'],
                max_age=settings.CSRF_COOKIE_AGE,
                domain=settings.CSRF_COOKIE_DOMAIN,
                path=settings.CSRF_COOKIE_PATH,
                secure=settings.CSRF_COOKIE_SECURE,
                httponly=settings.CSRF_COOKIE_HTTPONLY,
                samesite=settings.CSRF_COOKIE_SAMESITE,
            )
            # Set the Vary header since content varies with the CSRF cookie.
            patch_vary_headers(response, ('Cookie',))

    def process_response(self, request, response):
        if not getattr(request, 'csrf_cookie_needs_reset', False):
            if getattr(response, 'csrf_cookie_set', False):
                return response

        if not request.META.get("CSRF_COOKIE_USED", False):
            return response

        # Set the CSRF cookie even if it's already set, so we renew
        # the expiry timer.
        self._set_token(request, response)
        response.csrf_cookie_set = True
        return response


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
    exclude = ('AddrAPI.get',)

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

        print('[middleware] called_func_name', called_func_name)
        if request_path in APISecurityMiddleware.exclude or called_func_name in excluded_funcs\
                or called_func_name in APISecurityMiddleware.exclude:
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
