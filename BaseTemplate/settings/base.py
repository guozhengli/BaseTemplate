#!/usr/bin/env python
#coding=utf-8
from settings import *

###### my settings ######

# make root path

TIME_ZONE = 'Asia/Shanghai'

#LANGUAGE_CODE = 'zh-cn'
LANGUAGE_CODE = 'en-us'

# 关掉debug模式,需要配置allowed_hosts
DEBUG=True
ALLOWED_HOSTS = ['*']

SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_AGE = 3600*24

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'adminset',
    #'asset',
    #'rest_framework',
]
AUTH_USER_MODEL = 'adminset.UserPro'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'adminset.context_processors.prems',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

STATICFILES_DIRS = (
    os.path.join(BASE_DIR,'static'),
)

REST_FRAMEWORK = {
    # Use Django's standard `django.contrib.auth` permissions,
    # or allow read-only access for unauthenticated users.
    #'DEFAULT_MODEL_SERIALIZER_CLASS':
    #    'rest_framework.serializers.HyperlinkedModelSerializer',
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.DjangoModelPermissionsOrAnonReadOnly'
    ]
}

ERROR_MSG = {
    '1': u'错误号：1,没有这个用户',
    '2': u'错误号：2,没有足够的权限访问此页',
    '3': u'错误号：3,权限查找失败',
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s -- %(asctime)s %(module)s %(lineno)d  -- %(message)s'
        },
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': '/var/log/django.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'propagate': True,
            'level': 'INFO',
        },
        'django.request': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
