#!/usr/bin/env python
#coding:utf8 by guozheng_li
import time,struct,hmac,hashlib,base64,random
from adminset.models import  UserPro
import time,datetime

def generate_code (secretkey = '', value=None):
    '''
    算法：生成6个随机数
    :param secretkey:
    :param value:
    :return:
    '''
    value = value or int(time.time() / 3600)
    value = struct.pack('>q', value)

    secretkey = base64.b32decode(secretkey.upper())
    hash = hmac.new(secretkey, value, hashlib.sha1).digest()

    offset = ord(hash[-1]) & 0x0F
    truncated_hash = hash[offset:offset + 4]

    truncated_hash = struct.unpack('>L', truncated_hash)[0]
    truncated_hash &= 0x7FFFFFFF
    truncated_hash %= 1000000

    return '%06d' % truncated_hash
    #print generate_code('NVXVPS67VU3FUD4P')


def md5_google(jy):
    '''
    md5(md5+generate_code)
    :param jy:
    :return:
    '''
    yz = hashlib.md5(jy).hexdigest()
    goog =  generate_code(base64.b32encode(jy))
    newgoog = yz+goog
    MDF =  hashlib.md5(newgoog)
    return MDF.hexdigest().upper()


def users(user):
    '''
    查看user是否存在UserPro表中
    :param user:
    :return:
    '''
    userall = UserPro.objects.all()
    user_list = [i.name for i in userall]
    if user in user_list:
        return True
    else:
        return  False

def validation(token,loginuser):
    #new_token = md5_google('FXLSUCYFZLSVFKIL')
    user = UserPro.objects.get(name=loginuser).password
    new_token = hashlib.md5(user).hexdigest()
    if unicode(new_token.upper()) == token:
        return True
    else:
        return False

def rest_permission():
    '''
    token&user认证装饰器,判断是否有权限获取api数据
    :param view_func:
    :return:
    '''
    def _wrapped_view(request, *args, **kwargs):
        print request
        if True:
            print request
            #if request.session.get('user', ''):
            #    request.session.flush()
                #return redirect("/adminset/login")
            #else:
            #    print 'aaaaa'
            #    request.session.flush()
                #url = login_cas_url()
                #return redirect(url)
        else:
            #return view_func(request, *args, **kwargs)
            pass
    return _wrapped_view