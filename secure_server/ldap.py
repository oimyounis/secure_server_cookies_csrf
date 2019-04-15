import ldap
from django_auth_ldap.config import LDAPSearch, GroupOfNamesType

import logging

logger = logging.getLogger('django_auth_ldap')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)
# Baseline configuration.
AUTH_LDAP_SERVER_URI = "ldap://stats.gov.sa:389"

AUTH_LDAP_BIND_DN = "CN=ldpweb,CN=Users,DC=stats,DC=gov,DC=sa"
AUTH_LDAP_BIND_PASSWORD = "Windows.5085780"
# AUTH_LDAP_BIND_DN = "CN=ldpw,CN=Service Account,DC=stats,DC=gov,DC=sa"
# AUTH_LDAP_BIND_PASSWORD = "Password@123"
AUTH_LDAP_USER_SEARCH = LDAPSearch("DC=stats,DC=gov,DC=sa", ldap.SCOPE_SUBTREE, "(mail=%(user)s)")
# or perhaps:
# AUTH_LDAP_USER_DN_TEMPLATE = "uid=%(user)s,ou=users,dc=example,dc=com"

# Set up the basic group parameters.
AUTH_LDAP_GROUP_SEARCH = LDAPSearch("DC=stats,DC=gov,DC=sa", ldap.SCOPE_SUBTREE, "(objectClass=user)")
AUTH_LDAP_GROUP_TYPE = GroupOfNamesType()


# Populate the Django user from the LDAP directory.
AUTH_LDAP_USER_ATTR_MAP = {
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail",
}
# Cache group memberships for an hour to minimize LDAP traffic
AUTH_LDAP_CACHE_GROUPS = True
AUTH_LDAP_GROUP_CACHE_TIMEOUT = 3600

# Keep ModelBackend around for per-user permissions and maybe a local
# superuser.
AUTHENTICATION_BACKENDS = (
    'django_auth_ldap.backend.LDAPBackend',
    'django.contrib.auth.backends.ModelBackend',
)
ldap.set_option(ldap.OPT_REFERRALS, 0)
