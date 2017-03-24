# coding: utf-8

import logging
import json
import random
import arrow

#from django.conf import settings
from django.contrib import messages
from django.http import HttpResponse, Http404,HttpResponseRedirect
from django.shortcuts import render, redirect, get_object_or_404
#from django.contrib.auth.decorators import login_required
from django.contrib import auth
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

from .context_processors import prem_required
from .models import Role, Permissions, UserPro, SystemLog, Department, ForgotPassword
from .forms import RoleForm, LoginForm, PwresetForm, Pwreset_doForm, PasswordForm
from lib.helper import paginator, get_source_ip
from adminset.zgxcwlogin import cas_login_logout, cas_is_admin_api, cas_ticket, logout_cas_url
from adminset.zgxcwlogin import login_required_zgxcw as login_required

#from asset.models import Host

logger = logging.getLogger('django')

def forgotpassword(request):
    '''
    忘记密码 -- 发送邮件
    '''

    if request.method == 'POST':
        data = request.POST.copy()
        form = PwresetForm(request, data)
        source_ip = get_source_ip(request)
        if form.is_valid():
            ok = form.save()
            if ok:
                messages.info(request, u'发送邮件成功!')
                SystemLog.objects.add_log(form.cleaned_data.get("username", ""), operate=u'发送密码重置邮件',
                                          prem_context=u'申请ip地址:%s, 结果成功' % source_ip)
                return redirect('/')
            else:
                messages.info(request, u'发送邮件失败')

            SystemLog.objects.add_log(form.cleaned_data.get("username", ""), operate=u'发送密码重置邮件',
                                      prem_context=u'申请ip地址:%s, 结果失败' % source_ip)
            context = {'form': form, 'user_do': u'发送邮件'}
            return render(request, "adminset/forgot_password.html", context)
    else:
        form = PwresetForm(request)

    context = {'form': form, 'user_do': u'发送邮件'}
    return render(request, "adminset/forgot_password.html", context)

def forgotpassworddo(request):
    '''
    忘记密码 -- 修改密码页面
    '''

    rqcode = request.GET.get('code', '')
    request.session.flush()
    source_ip = get_source_ip(request)

    try:
        utcnow = arrow.utcnow()
        dbcode = ForgotPassword.objects.filter(code=rqcode).filter(created__range=(utcnow.replace(hours=-1).datetime, utcnow.datetime)).latest('id')
    except:
        messages.info(request, '重置密码链接已过期, 请重新通过邮箱找回密码！')
        context = { 'user_do': u'重置密码'}
        return render(request, "adminset/forgot_password.html", context)

    if request.method == 'POST':
        data = request.POST.copy()
        form = Pwreset_doForm(dbcode.username, data)
        if form.is_valid():
            form.save()
            dbcode.delete()
            messages.info(request, '重置密码成功!')
            SystemLog.objects.add_log(dbcode.username, operate=u'重置密码',
                                      prem_context=u'申请ip地址:%s, 结果成功' % source_ip)
            return redirect('/')

    else:
        form = Pwreset_doForm(dbcode.username)

    context = {'form': form, 'user_do': u'重置密码'}
    return render(request, "adminset/forgot_password.html", context)

@login_required(login_url='/login/')
def modify_password(request):
    '''
    用户修改密码
    '''
    username = request.session['user']
    user = UserPro.objects.get(name=username)
    if request.method == 'POST':
        data = request.POST.copy()
        form = PasswordForm(request, data)
        if form.is_valid():
            form.save()
            return redirect("login")
    else:
        form = PasswordForm(request)
    context = {
        'form': form,
        'user': user
    }

    return render(request, "adminset/modify_password.html", context)

def cas_login(request):
    '''
    cas认证页面
    '''
    context = {
        'cas_logout': logout_cas_url()
    }
    return render(request, "adminset/cas_login.html", context)


@cas_login_logout
def login(request):
    '''
    认证页面
    '''

    if request.method == 'POST':
        clientip=get_source_ip(request)
        data = request.POST.copy()
        form = LoginForm(request,data)
        if form.is_valid():
            user = form._user
            perm_s = []
            auth.login(request,user)
            try:
                user.ip = clientip
                user.save()
                if user:
                    per = UserPro.get_all_permissions(user)
                    for perm in per:
                        perm_s.append(str(perm))
            except:
                logger.error("username is Error")
            request.session['pvlg'] = perm_s
            request.session['user'] = user.name
            request.session['prems'] = user.get_all_premission()
            return redirect("/")
    else:
        form = LoginForm(request)
    context = {
        'form': form,
        'user_do': u'登录'
    }
    return render(request, "adminset/login.html", context)

def login_back(request):
    '''
    cas认证的回调地址
    '''
    ticket = request.GET.get('ticket', '')
    username = cas_ticket(ticket)
    if username:
        try:
            user = UserPro.objects.get(name=username)
        except:
            user = UserPro.objects.create_user(email='%s@zgxcw.com' % username, name=username, password=random.sample("abcdefghijklmnopqrstuvwxyz1234567890", 16))
            user.set_anonymous_department_role()

        clientip = request.META['REMOTE_ADDR']
        user.ip = clientip
        user.save()
        request.session.flush()
        request.session['user'] = username
        if cas_is_admin_api(username):
            request.session['prems'] = Permissions.objects.get_all_prems_name()
        else:
            request.session['prems'] = user.get_all_premission()
        return redirect("index")

    else:
        return redirect('/adminset/error/?id=2')

@cas_login_logout
def logout(request):
    '''
    返回登录页
    :param request:
    :return:
    '''
    auth.logout(request)
    return HttpResponseRedirect("/login/")


def error(request):
        '''
        报错页面
        '''

        errorid = request.GET.get('id')
        error_info = settings.ERROR_MSG.get(errorid)

        context = {
            "error": error_info
        }
        return render(request, "adminset/error.html", context)

def index(request):
    '''
    根登录访问页
    :param request:
    :return:
    '''
    user = request.session.get('user','')
    if not user:
        return redirect('login')
    datas = []
    #datas.append(Host.objects.get_host_type_chart_data())
    #datas.append(Host.objects.get_host_status_chart_data())
    context ={
        'user':user,
        #'datas':datas
    }
    return render(request, "index.html", context)


@login_required(login_url='/login/')
@prem_required(['can_role_manager'])
def roles_list(request):
    '''
    显示所有角色
    '''
    roles = Role.objects.all()
    context = {
        'roles': roles,
    }
    return render(request, "adminset/roles_list.html", context)

@login_required(login_url='/login/')
@prem_required(['can_role_manager'])
def del_role(request, id):
    '''
    删除角色
    '''

    role = get_object_or_404(Role, pk=id)
    SystemLog.objects.add_log(user=request.session['user'], operate=u'删除角色', prem_context=u'删除角色:%s' % role.name)
    role.delete()

    return redirect('roles_list')

@login_required(login_url='/login/')
@prem_required(['can_role_manager'])
def add_role(request):
    '''
    增加角色
    '''
    if request.method == 'POST':
        form = RoleForm(request.POST)
        if form.is_valid():
            form.save()
            SystemLog.objects.add_log(user=request.session['user'], operate=u'增加角色', prem_context=u'增加角色:%s' % form.cleaned_data['name'])
            return redirect('roles_list')
    else:
        form = RoleForm()

    context = {
        'form': form,
    }
    return render(request, "adminset/add_role.html", context)

@login_required(login_url='/login/')
@prem_required(['can_user_manager'])
def users_list(request):
    '''
    用户管理
    :param request:
    :return:
    '''
    users = UserPro.objects.all()
    context = {
        'users': users,
    }
    return render(request, "adminset/user_list.html", context)

@login_required(login_url='/login/')
@prem_required(['can_user_manager'])
def add_user(request):
    '''
    添加用户
    :param request:
    :return:
    '''

    loginuser = request.session['user']
    if request.method=='POST':
       if request.POST:
           full_name = request.POST['full_name']
           username = request.POST['username']
           password = request.POST['password']
           emails = request.POST['email']
           islogin = request.POST.get('islogin', False)
           department = request.POST['department']
           UserPro.objects.add_user(full_name, username, password, emails, islogin, department, loginuser)

           return redirect('users_list')

    departments = Department.objects.all()
    context = {
        'departments': departments
    }
    return render(request, "adminset/add_user.html", context)

@login_required(login_url='/login/')
@prem_required(['can_role_manager'])
def del_user(request, id):
    '''
    删除用户
    '''

    user = get_object_or_404(UserPro, pk=id)
    SystemLog.objects.add_log(user=request.session['user'], operate=u'删除用户', prem_context=u'删除用户:%s' % user.name)
    user.delete()

    return redirect('users_list')

@login_required(login_url='/login/')
@prem_required(['can_user_manager'])
def modify_user(request, id):
    '''
    用户编辑
    :param request:
    :return:
    '''
    loginuser = request.session['user']

    if request.method == 'POST':
        if request.POST:
            username = request.POST['username']
            email = request.POST['email']
            uid = request.POST['userid']
            departmentid = request.POST['departmentid']
            role = request.POST.getlist('role')
            try:
                islogin = request.POST['islogin']
            except:
                islogin = 'off'
            UserPro.objects.update_user(username, email, islogin, uid, departmentid, role, loginuser)
            return redirect('users_list')

    uid = UserPro.objects.get(id=int(id))
    gid = Department.objects.all()
    if uid.name == "root":
        roles = Role.objects.all().values_list('desc')
        roles = zip(*roles)[0]
    else:
        roles = uid.department.get_user_role()

    context = {
        'userinfo':uid,
        'groupinfo':gid,
        'roles':roles,
    }
    return render(request, "adminset/modify_user.html", context)

@csrf_exempt
@login_required(login_url='/login/')
@prem_required(['can_user_manager'])
def reset_password(request):
    '''
    重置密码
    '''
    if request.method == 'POST':
        uid = request.POST.get('uid')
        user = UserPro.objects.get(id=int(uid))
        user.set_password('123456')
        user.save()
        data = {
            "res": True
        }
        return HttpResponse(json.dumps(data), content_type="application/json")
    else:
        return HttpResponse(json.dumps({}), content_type="application/json")

@csrf_exempt
@login_required(login_url='/login/')
@prem_required(['can_user_manager'])
def get_roles_from_department(request):
    '''
    重置密码
    '''
    try:
        if request.method == 'POST':
            departmentid = request.POST.get('departmentid')
            department = Department.objects.get(id=int(departmentid))
            roles = department.get_user_role()
            data = {
                "roles": tuple(roles)
            }
            return HttpResponse(json.dumps(data), content_type="application/json")
        else:
            return HttpResponse(json.dumps({}), content_type="application/json")
    except:
        logger.error("reset pass error")

@login_required(login_url='/login/')
@prem_required(['can_user_manager'])
def del_user(request, id):
    '''
    删除角色
    '''

    user = get_object_or_404(UserPro, pk=id)
    SystemLog.objects.add_log(user=request.session['user'], operate=u'删除用户', prem_context=u'删除用户:%s' % user.name)
    user.delete()

    return redirect('users_list')


@login_required(login_url='/login/')
@prem_required(['can_department_manager'])
def department_list(request):
    '''
    部门列表
    :param request:
    :return:
    '''
    departments = Department.objects.all()
    context = {
        'departments': departments,
    }
    return render(request, "adminset/department_list.html", context)

@login_required(login_url='/login/')
@prem_required(['can_department_manager'])
def add_department(request):
    '''
    添加部门
    :param request:
    :return:
    '''
    user = request.session['user']
    users = UserPro.objects.all()
    perms = Role.objects.all()
    if request.method=='POST':
       if request.POST:
           inputusers = request.POST['inputusers']
           usersperm = request.POST.getlist('usersperm')
           manageproject = request.POST.getlist('manageproject')
           Department.objects.add_department(inputusers,usersperm,manageproject, user)
           return redirect('department_list')
    context = {
        'users':users,
        'perms':perms,
    }
    return render(request, "adminset/add_department.html", context)

@login_required(login_url='/login/')
@prem_required(['can_department_manager'])
def del_department(request, id):
    '''
    删除部门
    '''

    department = get_object_or_404(Department, pk=id)
    SystemLog.objects.add_log(user=request.session['user'], operate=u'删除部门', prem_context=u'删除部门:%s' % department.name)
    department.delete()

    return redirect('department_list')

@login_required(login_url='/login/')
@prem_required(['can_department_manager'])
def modify_department(request, id):
    '''
    修改部门信息
    :param request:
    :return:
    '''

    loginuser = request.session['user']
    uid = Department.objects.get(id=int(id))
    quanxianid = Role.objects.all()
    if request.method == 'POST':
        if request.POST:
            gid = request.POST.get('department_id', '')
            departmentgroups = request.POST.getlist('serverline')
            roles = request.POST.getlist('roles')
            department_name = request.POST.get('department_name', '')
            Department.objects.prem_department(gid,departmentgroups,roles,department_name, loginuser)
        return redirect('department_list')
    context = {
        "group": uid,
        'quanxianid':quanxianid,
    }
    return render(request, "adminset/modify_department.html", context)


@login_required(login_url='/login/')
@prem_required(['can_role_manager'])
def role_prem(request, id):
    '''
    role配置权限
    '''

    role = Role.objects.get(pk=int(id))

    if request.method == 'POST':
        prems_id = request.POST.getlist('prem')
        role.del_all_premission()
        for premid in prems_id:
            prem = Permissions.objects.get(pk=int(premid))
            role.add_premission(prem)

        if isinstance(prems_id,list):
            context = u",".join(prems_id)
        else:
            context = u"%s个" % len(prems_id)
        SystemLog.objects.add_log(user=request.session['user'], operate=u'角色配置权限',
                                      prem_context=u'角色:%s, 配置权限:%s' % (role.name, context))
        return redirect('roles_list')

    prems = Permissions.objects.get_all_prems()
    role_prems = role.get_all_premission()
    context = {
        'prems': prems,
        'role_prems': role_prems,
        'role': role,
    }

    return render(request, "adminset/role_prem.html", context)






@login_required(login_url='/login/')
def news(request):
    '''
    消息通知视图
    '''

    username = request.session.get('user')
    user = UserPro.objects.get(name=username)
    roles = user.get_all_role_name()

    if 'admin' in roles:
        oprecord = OpRecord.objects.filter(TaskId__status__Id__in=[1,2,5,6])
    else:
        oprecord = OpRecord.objects.filter(pk=-1)
        if user.has_verify_prem():
            user_Projects = user.get_self_department_project()
            oprecord |= OpRecord.objects.filter(TaskId__status__Id__in=[1,2], ProjId__verify=True, ServiceId__in=user_Projects)
        if user.has_pulish_prem():
            user_Projects = user.get_all_project()
            oprecord |= OpRecord.objects.filter(TaskId__status__Id__in=[1], ProjId__verify=False, ServiceId__in=user_Projects)
            oprecord |= OpRecord.objects.filter(TaskId__status__Id__in=[6, 5], ServiceId__in=user_Projects)
        if user.has_confirm_prem():
            user_Projects = user.get_all_project()
            oprecord |= OpRecord.objects.filter(TaskId__status__Id__in=[2], ServiceId__in=user_Projects)

    data = []

    for record in oprecord:
        data.append([record.Id, record.Name, record.ProjId.verify, record.TaskId.status.Id])

    context = {
        "oprecord": data,
    }
    return HttpResponse(json.dumps(context), content_type="application/json")

@login_required(login_url='/login/')
def documentation(request):
        '''
        文档
        :param request:
        :return:
        '''
        context = {
        }
        return render(request, "documentation.html", context)