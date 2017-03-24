#!/usr/bin/env python
#coding=utf-8

import requests
import urllib
import traceback
import logging

from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from django.conf import settings
import ssl
from urllib import urlencode, urlopen
from urlparse import urljoin
from xml.dom import minidom
logger = logging.getLogger('django')

def login_cas_url():
    '''
    登录时cas的url
    '''
    back_url = urllib.quote_plus(settings.LOING_BACK)
    cas_url = "%s/login?service=%s" % (settings.CAS_SERVER, back_url)
    return cas_url

def logout_cas_url():
    '''
    注销用户
    :return:
    '''
    url = urljoin(settings.CAS_SERVER, 'logout')
    return url

def cas_ticket(ticket=''):
    '''
    cas ticktet 确认函数
    '''

    url = settings.CAS_SERVER
    args = {
        "ticket": ticket,
        "service": settings.LOING_BACK,
    }
    try:

        context = ssl._create_unverified_context()
        page = urlopen(urljoin(url, 'proxyValidate') + '?' + urlencode(args), context=context)
        page_centext = page.read()
        response = minidom.parseString(page_centext)
        username = response.getElementsByTagName('cas:user')[0].firstChild.nodeValue
        return username
    except Exception,e:
        return ""

def cas_user_required(*args, **kwargs):
    '''
    cas认证装饰器
    '''
    def decorator(view_func):
        def _wrapped_view(request, *args, **kwargs):
            if request.session.get('user', ''):
                return view_func(request, *args, **kwargs)
            request.session.flush()
            cas_url = login_cas_url()
            return redirect(cas_url)
        return _wrapped_view
    return decorator


def login_required_zgxcw(*args, **kwargs):
    '''
    诸葛认证装饰器, 增加cas认证中心
    '''

    if settings.LOGIN_BY == "CAS":
        return cas_user_required(*args, **kwargs)
    else:
        return login_required(*args, **kwargs)


def cas_login_logout(view_func):
    '''
        登录和注销装饰器,判断是进入cas认证还是本地认证
    '''
    def _wrapped_view(request, *args, **kwargs):
        if settings.LOGIN_BY == "CAS":
            if request.session.get('user', ''):
                request.session.flush()
                return redirect("cas_login")
            else:
                request.session.flush()
                url = login_cas_url()
                return redirect(url)
        else:
            return view_func(request, *args, **kwargs)
    return _wrapped_view

def cas_is_admin_api(user):
    '''
    cas api: 查询用户是否属于最高管理员
    :param user: 用户名
    :return: bool
    '''
    url = settings.CAS_API
    args = {
        'user': user,
        'application': settings.APPLICATION_NAME
    }
    try:
        res = requests.get(url, params=args).json()
        if type(res) == type({}):
            if "owner" in res['role']:
                return True
        return False
    except Exception,e:
        logger.error("cas api err: %s" % e)
        return False
