#coding=utf-8

from django.shortcuts import redirect
from django.conf import settings

def additional_condition(prem):
    return True

def is_local_auth(prem):
    '''
    判断是本地认证还是其他认证
    :param prem:
    :return:
    '''
    if settings.LOGIN_BY == "SYSTEM":
        prem['can_local_auth'] = True


def prems(request):
    '''
    权限控制全局变量
    应用在template中
    :return:
    '''
    current_prems = request.session.get('prems')

    def format_prems(current_prems):
        if current_prems == None or current_prems == "":
            return {}
        if isinstance(current_prems, list):
            prems_list = current_prems
        elif isinstance(current_prems, str):
            prems_list = current_prems.strip().split(';')
        elif isinstance(current_prems, unicode):
            prems_list = current_prems.strip().split(';')
        prems_dict = {}
        for prem in prems_list:
            if additional_condition(prem):
                prems_dict[prem] = True

        is_local_auth(prems_dict)
        return prems_dict

    context = {
        'current_prems': format_prems(current_prems)
    }
    return context



def prem_required(check_prems):
    '''
    权限控制装饰器，应用在views视图中
    :param prems: 权限列表
    :return:
    '''
    def wrapped(func):
        def _wrapper(request,*args, **kwargs):
            current_prems = request.session.get('prems')
            for prem in check_prems:
                if prem in current_prems and additional_condition(prem):
                    continue
                else:
                    return redirect('/adminset/error/?id=2')
            return func(request,*args, **kwargs)

        return _wrapper
    return wrapped

