#!/usr/bin/env python
#coding=utf-8
import sys

from base import *



DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql', # Add 'postgresql_psycopg2', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': '',                      # Or path to database file if using sqlite3.
        'USER': '',                      # Not used with sqlite3.
        'PASSWORD': '',                  # Not used with sqlite3.
        'HOST': '',                      # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '',                      # Set to empty string for default. Not used with sqlite3.
        'OPTIONS':{
            'connect_timeout': 10,
        }
    },
}


# LOGIN the way login like SYSTEM, CAS
#LOGIN_BY = 'SYSTEM'
LOGIN_BY = 'CAS'

# cas 参数
CAS_SERVER = 'https://passport.zgxcw-inc.com'
LOING_BACK = 'http://172.31.102.144:8080/adminset/login_back'
APPLICATION_NAME = "asset"
CAS_API = 'http://mis.zgxcw-inc.com/ldap-service/api/userRoleOfApplication'
CAS_MODIFY_PASSWORD = 'http://mis.zgxcw-inc.com/ldap-service/index'


HOST_MODEL = (
    (0, '物理机'),
    (1, 'KVM虚拟机'),
)

OS_MODEL = (
    (0,'Linux'),
    (1,'Windows')
)

# 邮箱参数
ADMINSET_MAIL_SERVER = 'smtp.exmail.qq.com'
ADMINSET_MAIL_PORT = 465
ADMINSET_MAIL_USER = ''
ADMINSET_MAIL_PASSWORD = ''