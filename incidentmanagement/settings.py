# """
# Django settings for incidentmanagement project.

# Generated by 'django-admin startproject' using Django 5.1.1.

# For more information on this file, see
# https://docs.djangoproject.com/en/5.1/topics/settings/

# For the full list of settings and their values, see
# https://docs.djangoproject.com/en/5.1/ref/settings/
# """

# from pathlib import Path
# import os
# from datetime import timedelta

# # Build paths inside the project like this: BASE_DIR / 'subdir'.
# BASE_DIR = Path(__file__).resolve().parent.parent


# # Quick-start development settings - unsuitable for production
# # See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# # SECURITY WARNING: keep the secret key used in production secret!
# SECRET_KEY = 'django-insecure-544!p1hn*4-5wf2)b+y+(t8$w)8p)sh4o!fu^^ecdg@$%ddbgs'

# # SECURITY WARNING: don't run with debug turned on in production!
# DEBUG = True

# ALLOWED_HOSTS = ['*','127.0.0.1','localhost','172.16.16.64',"https://incident.stratapps.com","https://hask.app","hask.app"]

# AUTH_USER_MODEL = "core.UserProfile"

# # Application definition

# INSTALLED_APPS = [
#     'django.contrib.admin',
#     'django.contrib.auth',
#     'django.contrib.contenttypes',
#     'django.contrib.sessions',
#     'django.contrib.messages',
#     'django.contrib.staticfiles',
    
#     'core',
#     'rest_framework',
#     'corsheaders',
#     'rest_framework.authtoken',  # Add this for token authentication

#     'knox',
# ]

# # REST_FRAMEWORK = {
# #     'DEFAULT_AUTHENTICATION_CLASSES': (
# #         'rest_framework.authentication.TokenAuthentication',
# #         'rest_framework.authentication.SessionAuthentication',
# #         # Other authentication classes if needed
# #     ),
# #     'DEFAULT_PERMISSION_CLASSES': (
# #         'rest_framework.permissions.IsAuthenticated',
# #     ),
# # }
# REST_FRAMEWORK = {
#     'DEFAULT_AUTHENTICATION_CLASSES': (
#         'knox.auth.TokenAuthentication',
#         'rest_framework.authentication.SessionAuthentication',
#         'rest_framework.authentication.BasicAuthentication',
#     ),
#     'DEFAULT_PERMISSION_CLASSES': [
#         'rest_framework.permissions.IsAuthenticated',  # Require authentication by default
#     ],
# }

# AUTHENTICATION_BACKENDS = [
#     'django.contrib.auth.backends.ModelBackend',
# ]


# MIDDLEWARE = [
#     'django.middleware.security.SecurityMiddleware',
#     'django.contrib.sessions.middleware.SessionMiddleware',
#     'django.middleware.common.CommonMiddleware',
#     'django.middleware.csrf.CsrfViewMiddleware',
#     'django.contrib.auth.middleware.AuthenticationMiddleware',
#     'django.contrib.messages.middleware.MessageMiddleware',
#     'django.middleware.clickjacking.XFrameOptionsMiddleware',
#     'corsheaders.middleware.CorsMiddleware',
#     'django.middleware.common.CommonMiddleware',
#     'incidentmanagement.middleware.LogHeadersMiddleware',  # Add your middleware here

# ]


# MIDDLEWARE.insert(0, 'corsheaders.middleware.CorsMiddleware')

# # REST_KNOX = {
# #   'SECURE_HASH_ALGORITHM': 'cryptography.hazmat.primitives.hashes.SHA512',
# #   'AUTH_TOKEN_CHARACTER_LENGTH': 8,
# #   'TOKEN_TTL': timedelta(minutes=120),
# #   'USER_SERIALIZER': 'knox.serializers.UserSerializer',
# #   'TOKEN_LIMIT_PER_USER': None,
# #   'AUTO_REFRESH': False,
# # #   'EXPIRY_DATETIME_FORMAT': api_settings.DATETME_FORMAT,
# # }

# import hashlib

# REST_KNOX = {
#     'SECURE_HASH_ALGORITHM': 'hashlib.sha512',  # Use hashlib's SHA512
#     'AUTH_TOKEN_CHARACTER_LENGTH': 8,
#     'TOKEN_TTL': timedelta(minutes=120),
#     'USER_SERIALIZER': 'knox.serializers.UserSerializer',
#     'TOKEN_LIMIT_PER_USER': None,
#     'AUTO_REFRESH': False,
# }
# # REST_KNOX = {
# #     'TOKEN_TTL': None,  # Tokens don't expire by default
# #     'TOKEN_LIMIT_PER_USER': None,  # No limit to tokens per user
# #     'HASH_ALGORITHM': 'sha256',  # Use SHA256 instead of SHA512
# #     'AUTH_HEADER_PREFIX': 'Token',
# # }

# ROOT_URLCONF = 'incidentmanagement.urls'

# TEMPLATES = [
#     {
#         'BACKEND': 'django.template.backends.django.DjangoTemplates',
#         'DIRS': [os.path.join(BASE_DIR,"templates")],
#         'APP_DIRS': True,
#         'OPTIONS': {
#             'context_processors': [
#                 'django.template.context_processors.debug',
#                 'django.template.context_processors.request',
#                 'django.contrib.auth.context_processors.auth',
#                 'django.contrib.messages.context_processors.messages',
#             ],
#         },
#     },
# ]

# WSGI_APPLICATION = 'incidentmanagement.wsgi.application'


# # Database
# # https://docs.djangoproject.com/en/5.1/ref/settings/#databases

# # DATABASES = {
# #     'default': {
# #         'ENGINE': 'django.db.backends.sqlite3',
# #         'NAME': BASE_DIR / 'default.sqlite3',
# #     },
# # }

# DATABASES = {
#    'default': {
#         'ENGINE': 'django.db.backends.postgresql_psycopg2',
#         'NAME': 'IncidentCore', 
#         'USER': 'postgres',
#         'PASSWORD': 'QP3HeJel62BPzPaq07uETezy',
#         'HOST': 'e-commerce.cj3oddyv0bsk.us-west-1.rds.amazonaws.com', 
#         'PORT': '5432',
#     }
# }


# # Password validation
# # https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

# AUTH_PASSWORD_VALIDATORS = [
#     {
#         'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
#     },
#     {
#         'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
#     },
#     {
#         'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
#     },
#     {
#         'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
#     },
# ]

# PASSWORD_HASHERS = [
#     'django.contrib.auth.hashers.PBKDF2PasswordHasher',
#     'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
#     'django.contrib.auth.hashers.Argon2PasswordHasher',
#     'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
# ]

# # Internationalization
# # https://docs.djangoproject.com/en/5.1/topics/i18n/

# LANGUAGE_CODE = 'en-us'

# TIME_ZONE = 'UTC'

# USE_I18N = True

# USE_TZ = True


# # Static files (CSS, JavaScript, Images)
# # https://docs.djangoproject.com/en/5.1/howto/static-files/

# STATIC_URL = 'static/'

# # Default primary key field type
# # https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

# DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# # ConnectWise Details
# ConnectWiseClientId = "006d3e9d-26aa-461b-914c-1b6901beea3b"
# ConnectWiseAPIUrl = "https://api-staging.connectwisedev.com/v2022_2/apis/3.0/"

# # HaloPSA Details 
# HaloPSAAPIUrl = "https://xamplify.halopsa.com/api"

# TestConnectWiseCredentialsViaURL = "https://api-staging.connectwisedev.com/v2022_2/apis/3.0/service/tickets"

# TestHaloPSACredentialsViaURL = "https://xamplify.halopsa.com/auth/token"


# SECURE_CROSS_ORIGIN_OPENER_POLICY=None

# # Value determines whether the server allows cookies in the cross-site HTTP requests
# CORS_ALLOW_CREDENTIALS = True
# CORS_ALLOW_ALL_ORIGINS = True  # Use this for development

# CORS_ALLOWED_ORIGINS = [
#     "http://localhost:4200",
#     "http://127.0.0.1:5000",
#     "https://hask.app",
#     "https://incident.stratapps.com"
# ]

# CSRF_TRUSTED_ORIGINS = [
#     'http://localhost:4200',
#     "https://hask.app",
#     "https://incident.stratapps.com"
# ]


# # Methods allowed for CORS
# CORS_ALLOW_METHODS = [
#     'DELETE',
#     'OPTIONS',
#     'PATCH',
#     'GET',
#     'POST',
#     'PUT',  
# ]

# # Non-standard headers allowed in the request
# CORS_ALLOW_HEADERS = [
#     'accept',
#     'accept-encoding',
#     'authorization',
#     'content-type',
#     'dnt',
#     'origin',
#     'user-agent',
#     'x-csrftoken',
#     'x-requested-with',
#     'Authorization',
#     'Content-Type'
# ]

# APPEND_SLASH=False

# BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# MEDIA_URL = '/'  # This is the URL path for accessing media files
# MEDIA_ROOT = os.path.join(BASE_DIR, 'logos')  # This points to the logos directory
"""
Django settings for incidentmanagement project.
"""

import os
from pathlib import Path
from datetime import timedelta

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Security settings
SECRET_KEY = 'django-insecure-544!p1hn*4-5wf2)b+y+(t8$w)8p)sh4o!fu^^ecdg@$%ddbgs'
DEBUG = True
ALLOWED_HOSTS = ['*', '127.0.0.1', 'localhost', '172.16.16.64', 
                 'https://incident.stratapps.com', 'https://hask.app', 'hask.app']

# Custom user model
AUTH_USER_MODEL = "core.UserProfile"

# Application definitions
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party apps
    'rest_framework',
    'rest_framework.authtoken',
    'corsheaders',
    'knox',

    # Local apps
    'core',
]

# REST framework configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'knox.auth.TokenAuthentication',  # Knox token-based authentication
        'rest_framework.authentication.SessionAuthentication',  # For sessions
        'rest_framework.authentication.BasicAuthentication',  # For basic auth
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        # 'rest_framework.permissions.IsAuthenticated',  # Requires authentication
    ],
}

# Knox-specific settings
REST_KNOX = {
    # # 'SECURE_HASH_ALGORITHM': 'cryptography.hazmat.primitives.hashes.SHA256',
    # 'SECURE_HASH_ALGORITHM': 'hashlib.sha512',
    'AUTH_TOKEN_CHARACTER_LENGTH': 8,
    'TOKEN_TTL': timedelta(minutes=120),
    'USER_SERIALIZER': 'knox.serializers.UserSerializer',
    'TOKEN_LIMIT_PER_USER': None,
    'AUTO_REFRESH': False,
}

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
]

# Middleware
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  # Enable CORS
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# URL configuration
ROOT_URLCONF = 'incidentmanagement.urls'

# Template settings
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, "templates")],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# WSGI application
WSGI_APPLICATION = 'incidentmanagement.wsgi.application'

# Database configuration
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql_psycopg2',
#         'NAME': 'IncidentCore',
#         'USER': 'postgres',
#         'PASSWORD': 'QP3HeJel62BPzPaq07uETezy',
#         'HOST': 'e-commerce.cj3oddyv0bsk.us-west-1.rds.amazonaws.com',
#         'PORT': '5432',
#     }
# }
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'default.sqlite3',
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Password hashers
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
]

# Localization settings
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static and media files
STATIC_URL = 'static/'
MEDIA_URL = '/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'logos')

# CORS configuration
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = True  # Enable all origins for development
CORS_ALLOWED_ORIGINS = [
    "http://localhost:4200",
    "http://127.0.0.1:5000",
    "https://hask.app",
    "https://incident.stratapps.com",
]
CSRF_TRUSTED_ORIGINS = [
    'http://localhost:4200',
    "https://hask.app",
    "https://incident.stratapps.com",
]
CORS_ALLOW_METHODS = ['DELETE', 'OPTIONS', 'PATCH', 'GET', 'POST', 'PUT']
CORS_ALLOW_HEADERS = [
    'accept', 'accept-encoding', 'authorization', 'content-type', 'dnt', 
    'origin', 'user-agent', 'x-csrftoken', 'x-requested-with'
]

# Default auto field
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Additional settings for external integrations
ConnectWiseClientId = "006d3e9d-26aa-461b-914c-1b6901beea3b"
ConnectWiseAPIUrl = "https://api-staging.connectwisedev.com/v2022_2/apis/3.0/"
HaloPSAAPIUrl = "https://xamplify.halopsa.com/api"
TestConnectWiseCredentialsViaURL = "https://api-staging.connectwisedev.com/v2022_2/apis/3.0/service/tickets"
TestHaloPSACredentialsViaURL = "https://xamplify.halopsa.com/auth/token"

APPEND_SLASH = False
SECURE_CROSS_ORIGIN_OPENER_POLICY = None

# Email Configrations
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_USE_TLS = True
EMAIL_PORT = 587
EMAIL_HOST_USER = 'pakshay@stratapps.com' # Add Authorized Email
EMAIL_HOST_PASSWORD = 'AKShay@stratapps' #Add Authorized Password
