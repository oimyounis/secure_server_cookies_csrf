# email settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
# EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'   #for development test
EMAIL_HOST = 'gstat-ex01.stats.gov.sa'
EMAIL_PORT = 25
EMAIL_HOST_USER = ''
EMAIL_HOST_PASSWORD = ''
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False
EMAIL_TIMEOUT = None
EMAIL_SSL_CERTFILE = None  # specify the path to a PEM-formatted certificate chain file to use for the SSL connection.
EMAIL_SSL_KEYFILE = None  # specify the path to a PEM-formatted private key file to use for the SSL
FILE_CHARSET = 'utf-8'
FILE_UPLOAD_MAX_MEMORY_SIZE = 2621440  # (i.e. 2.5 MB).
