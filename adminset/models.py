#coding:utf8
from __future__ import unicode_literals
from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)
import django
from lib.helper import paginator


class PermissionsManager(models.Manager):

    def add_premissions(self, name, desc):
        '''
        增加一个权限
        '''
        premissions = Permissions(
            name=name,
            desc=desc
        )
        premissions.save()

    def get_prems_list(self):
        '''
        获取权限的列表
        '''
        prems_list = self.all().values_list('name', 'desc')
        return prems_list

    def get_all_prems(self):
        '''
        获取权限
        '''
        prems = self.all()
        return prems

    def get_all_prems_name(self):
        '''
        获取所有权限名
        :return:
        '''
        prems_list = self.all().values_list('name')
        if prems_list:
            return list(zip(*prems_list)[0])
        else:
            return []

class Permissions(models.Model):
    '''
    权限类
        与 角色 是多对多关系
    '''

    name = models.CharField(u'权限名', max_length=32, unique=True)
    parentid = models.IntegerField(u"权限id", default=-1)
    desc = models.CharField(u'描述', max_length=32)

    objects = PermissionsManager()

    def __unicode__(self):
        return "%s - %s" % (self.name, self.desc)

class DepartmentManager(models.Manager):
    '''
    部门类
    '''
    def get_department_name(self,department_name):
        '''
        判断users_name是否存在部门列表中，
            不存在则返回True可创建，
            存在则返回False不可创建
        :return:
        '''
        user_list = []
        user_names = Department.objects.all()
        for dname in user_names:
            if department_name == dname.name:
                return False
            user_list.append(dname)
        return True

    def get_department_list(self, paginate_num=12, page_num=1):
        '''
        获取flow分页列表
        :param paginate_num: 每页显示行数
        :param page_num: 当前页数
        :return:
        '''
        roles = self.all()
        return paginator(roles, paginate_num, page_num)

    def add_department(self,inputusers,usersperm,manageproject,user):
        '''
        添加部门(新建部门使用)
        :param inputusers: 部门
        :param usersperm:  部门权限
        :param manageproject: 项目所属部门
        :return:
        '''
        if Department.objects.get_department_name(inputusers):
            users = Department(name=inputusers)
            users.save()
            for mproject in usersperm:
                ptobject = Role.objects.get(desc=mproject)
                users.role_set.add(ptobject)
            #操作记录
            operate = u'部门添加'
            SystemLog.objects.add_log(user,operate,inputusers)

        return

    def prem_department(self,gid,departmentgroups,roles,department_name,loginuser):
        '''
        #部门修改
        :param gid:
        :param departmentgroups:
        :param roles:
        :return:
        '''
        groupid = Department.objects.get(id=gid)
        groupid.name = department_name
        groupid.save()
        rol = Role.objects.all()

        for i in rol:
            groupid.role_set.remove(i)

        for mproject in roles:
            ptobject = Role.objects.get(desc=mproject.strip())
            groupid.role_set.add(ptobject)

        #操作记录
        operate = u'部门修改'
        prem_context = '%s,%s,%s'%(roles, departmentgroups, department_name)
        SystemLog.objects.add_log(loginuser, operate, groupid.name, prem_context)

class Department(models.Model):
    '''
    部门类
        与 UserPro 是一对多关系。 一个部门对应对个user
        与 角色 是多对多关系
        与 一级项目 是多对多关系
    '''
    name = models.CharField(u'部门名称', max_length=32, unique=True)

    objects = DepartmentManager()

    def __unicode__(self):
        return self.name

    def get_all_role(self):
        '''
        获取部门内的所有角色
        :reture
        '''
        roles = self.role_set.all()
        return roles

    def get_user_role(self):
        '''
        获取部门内的当前角色
        :reture
        '''
        role = self.role_set.values_list('desc')
        return  zip(*role)[0]

    def get_user_type(self):
        '''
        获取内的当前组的项目
        :reture
        '''
        type = self.project_type_set.values_list('Name')
        return zip(*type)[0]

    def get_all_user(self):
        '''
        获取部门内的所有用户
        :return:
        '''
        users = self.userpro_set.all()
        return users

    def get_all_project(self):
        '''
        获取部门内的所有项目
        :return:
        '''
        projects = []
        first_projects = self.project_type_set.all()
        for first_project in first_projects:
            project = first_project.service_set.all()
            projects += project

        return projects

    def add_role(self, role):
        '''
        向部门中增加角色
        '''
        self.role_set.add(role)

    def GetRoleName(self):
        cc = Department.objects.get(id)
        role = cc.role_set.values()[0]['desc']
        return role

class UserManager(BaseUserManager):
    def create_user(self, email, name, aliasname='',password=None):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            aliasname=aliasname,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password, aliasname=''):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(email=email,
            password=password,
            name=username,
            aliasname=aliasname,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user

    def has_user_name(self,user_name):
        '''
        判断user_name是否存在用户列表中，不存在则返回False可创建用户，存在则返回True不可创建用户
        :return:
        '''
        try:
            UserPro.objects.get(name=user_name)
            return True
        except:
            return False

    def get_user_list(self, paginate_num=12, page_num=1):
        '''
        获取flow分页列表
        :param paginate_num: 每页显示行数
        :param page_num: 当前页数
        :return:
        '''
        roles = self.all()
        return paginator(roles, paginate_num, page_num)

    def add_user(self, full_name, username, password, email, islogin, department,loginuser):
        '''
        #添加用户(新建用户使用)
        :param firstnames: 中文名称
        :param inpname: 用户名
        :param inppwd: 密码
        :param emails: 邮箱
        :param istrue: 是否允许登录
        :department:关联部门
        :return:
        '''
        if not UserPro.objects.has_user_name(username):
            user = UserPro.objects.create_user(name=username, email=email, password=password, aliasname=full_name)
            if islogin == 'on':
                user.is_active = True
            else:
                user.is_active = False

            department = Department.objects.get(name=department)
            department.userpro_set.add(user)
            #添加操作记录
            operate = u'添加用户'
            SystemLog.objects.add_log(loginuser, operate, username)
            user.save()
        return

    def update_user(self,username, email, islogin, uid, departmentid, roles, loginuser):
        '''
        修改用户信息
        :param username:  用户名
        :param email:  邮箱
        :param islogin:  是否允许登陆
        :param uid: 用户uid
        :param department:  部门
        :param roles: 角色
        :param loginuser: 操作用户
        :return:
        '''
        userid = UserPro.objects.get(id=uid)
        department = Department.objects.get(id=int(departmentid))
        department.userpro_set.add(userid)
        rol = Role.objects.all()

        for i in rol:
            userid.role_set.remove(i)

        if islogin == 'on':
            usid = UserPro.objects.filter(id=uid).update(name=username,email=email,is_active=1)
        else:
            usid = UserPro.objects.filter(id=uid).update(name=username,email=email,is_active=0)

        for mproject in roles:
            ptobject = Role.objects.get(desc=mproject)
            userid.role_set.add(ptobject)

        #修改用户操作记录
        operate = u'用户修改'
        role = ",".join(roles)
        prem_context = role + department.name + email
        SystemLog.objects.add_log(loginuser, operate, username, prem_context)

class UserPro(AbstractBaseUser):
    '''
    用户类
        与 部门 是一对多关系
        与 角色 是多对多关系
        与 项目 是多对多关系
    '''
    name = models.CharField(verbose_name=u'用户名',
                            max_length=32,
                            unique=True)

    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    aliasname = models.CharField(u'中文名字', max_length=32)
    email = models.EmailField(max_length=255,)
    token = models.CharField(u'token', max_length=128,default=None,blank=True,null=True)
    #token_time = models.DateTimeField(default=django.utils.timezone.now)
    department = models.ForeignKey(Department,blank=True,null=True, on_delete=models.SET_NULL)
    ip = models.CharField(u'IP地址', max_length=32,default=None,blank=True,null=True)
    memo = models.TextField(u'备注', blank=True,null=True,default=None)
    login_time = models.DateTimeField(u'最后一次登录时间', auto_now=True)

    USERNAME_FIELD = 'name'
    REQUIRED_FIELDS = ['email']

    objects = UserManager()

    def set_anonymous_department_role(self):
        '''
        设置匿名角色和部门
        :return:
        '''
        anonymous_department = Department.objects.get(name ='anonymousdepartment')
        anonymous_role = Role.objects.get(name='anonymousrole')
        self.department = anonymous_department
        self.add_role(anonymous_role)
        self.save()

    def get_full_name(self):
        # The user is identified by their email address
        return self.name

    def get_short_name(self):
        # The user is identified by their email address
        return self.name

    def __str__(self):              # __unicode__ on Python 2
        return self.name

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True
    def has_perms(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True
    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin

    def __unicode__(self):
        return self.name

    def get_all_project(self):
        '''
        获取的所有权限所有项目
        :return:
        '''
        projects = self.service_set.all()
        return projects

    def get_all_premission(self):
        '''
        获取用户的所有权限
        :return:
        '''
        prems = []
        roles = self.role_set.all()
        for role in roles:
            prems += role.get_all_premission_name()
        return prems

    def get_all_premission_desc(self):
        '''
        获取用户的所有权限
        :return:
        '''
        prems = []
        roles = self.role_set.all()
        for role in roles:
            prems += role.get_all_premission_desc()
        return prems

    def prem_can(self, prem):
        '''
        判断用户是否存在此权限
        '''
        prems = self.get_all_premission()
        if prem in prems:
            return True
        else:
            return False


    def add_role(self, role):
        '''
        用户增加一个角色
        '''
        self.role_set.add(role)

    def del_role(self, role):
        '''
        用户删除一个角色
        '''
        self.role_set.remove(role)

    def add_project(self, project):
        '''
        用户增加一个项目
        '''
        self.service_set.add(project)

    def del_project(self, project):
        '''
        用户删除一个项目
        '''
        self.service_set.remove(project)

    def get_all_role(self):
        '''
        获取所有角色
        :return:
        '''
        role = self.role_set.all()
        return role

    def get_user_role(self):
        '''
        获取当前用户角色
        :return:
        '''
        role_list = []
        role = self.role_set.values_list()
        for r in role:
            role_list.append(r[1])
        return role_list

    def get_user_role_name(self):
        '''
        获取当前用户角色
        :return:
        '''
        role_list = []
        role = self.role_set.values_list('desc')
        if len(role) > 0:
            return zip(*role)[0]
        else:
            return ()

    def get_all_role_name(self):
        '''
        获取所有角色
        :return:
        '''
        role = self.role_set.all().values_list('name')
        return zip(*role)[0]

    def get_self_department_user(self):
        '''
        得到本部门内的其他成员
        '''
        if 'admin' in self.get_all_role_name():
            users = UserPro.objects.all().exclude(pk=self.id)
            return users
        else:
            try:
                users = UserPro.objects.filter(department__id=self.department.id).exclude(pk=self.id)
            except:
                return []
            return users

    def get_self_department_project(self):
        '''
        获取所在部门的所有项目
        :return:
        '''

        try:
            projects = self.department.get_all_project()
        except:
            return []
        return projects


    def del_all_projects(self):
        '''
        删除用户和所有项目的关系
        :return:
        '''

        projects = self.get_all_project()
        for project in projects:
            self.del_project(project)

    def is_department_admin(self):
        '''
        判断用户是不是部门管理员
        *** 如果是root用户单独判断
        :return:
        '''
        if 'can_access_manager' in self.get_all_premission():
            return True
        else:
            return False

    def has_verify_prem(self):
        '''
        是否有审核权限
        '''
        if 'can_task_verify' in self.get_all_premission():
            return True
        else:
            return False


    def has_pulish_prem(self):
        '''
        是否有发布权限
        '''
        if 'can_task_pulish' in self.get_all_premission():
            return True
        else:
            return False

    def has_confirm_prem(self):
        '''
        是否有确认权限
        '''
        if 'can_task_confirm' in self.get_all_premission():
            return True
        else:
            return False


    def get_all_department_serviceline(self):
        '''
        得到部门所有的业务线
        :return:
        '''
        try:
            res = self.department.project_type_set.all()
        except:
            res = []

        return res


class RoleManager(models.Manager):

    def get_role_list(self, paginate_num=12, page_num=1):
        '''
        获取flow分页列表
        :param paginate_num: 每页显示行数
        :param page_num: 当前页数
        :return:
        '''
        roles = self.all()
        return paginator(roles, paginate_num, page_num)

class Role(models.Model):
    '''
    角色类
        与 UserPro用户 是多对多关系
        与 部门 是多对多关系
    '''
    name = models.CharField(u'角色名', max_length=32, unique=True)
    desc = models.CharField(u'描述', max_length=255, unique=True)
    permissions = models.ManyToManyField(Permissions)
    role_user = models.ManyToManyField(UserPro)
    department = models.ManyToManyField(Department)

    objects = RoleManager()

    def __unicode__(self):
        return self.name



    def get_all_premission(self):
        '''
        获取所有的权限
        :return:
        '''

        prems = self.permissions.all()
        return prems

    def get_all_premission_name(self):
        '''
        获取所有的权限
        :return: 返回权限 name的列表
        '''
        prems = self.permissions.all().values_list('name')

        if prems:
            return list(zip(*prems)[0])
        else:return []

    def get_all_premission_desc(self):
        '''
        获取所有的权限
        :return: 返回权限 name的列表
        '''
        prems = self.permissions.all().values_list('desc')

        return list(zip(*prems)[0])

    def add_premission(self, prem):
        '''
        向角色中添加权限
        :return:
        '''

        self.permissions.add(prem)

    def del_all_premission(self):
        '''
        删除全部权限
        :return:
        '''
        prems = self.permissions.all()
        for prem  in prems:
            self.permissions.remove(prem)



class SystemLogManager(models.Manager):

     def add_log(self, user='', operate='', prem_user='' ,prem_context=''):
        '''
        添加用户时更新系统日志
        :param user:
        :param operate:
        :param date:
        :param prem_user:
        :param prem_context:
        :return:
        '''
        SystemLog(
            user=user,
            operate=operate,
            prem_user=prem_user,
            prem_context=prem_context
        ).save()

class SystemLog(models.Model):
    '''
    系统日志
    '''
    user = models.CharField(u'用户', max_length=60)
    operate = models.CharField(u'操作', max_length=60)
    date = models.DateTimeField(u'操作时间', auto_now_add=True)
    prem_user = models.CharField(u'被授权人', max_length=20)
    prem_context = models.CharField(u'授权内容', max_length=255)

    objects = SystemLogManager()

    def __unicode__(self):
        return self.operate

class TaskLogManager(models.Manager):

     def add_log(self,user='', operate='', taskid='' , operate_context=''):
        '''
        添加用户时更新系统日志
        :param user:
        :param operate:
        :param date:
        :param prem_user:
        :param prem_context:
        :return:
        '''
        TaskLog(
            user=user,
            operate=operate,
            taskid=taskid,
            operate_context=operate_context,
        ).save()



class TaskLog(models.Model):
    '''
    用户操作记录
    '''
    user = models.CharField(u'用户', max_length=60)
    operate = models.CharField(u'操作', max_length=60)
    date = models.DateTimeField(u'操作时间', auto_now_add=True)
    taskid = models.IntegerField(u"任务id", default=0)
    operate_context = models.CharField(u'操作内容', max_length=255)

    objects = TaskLogManager()

    def __unicode__(self):
        return self.operate


# 重置密码url的key， 重置密码 1 小时有效期
# 登陆失败的标志 xxx_login_false , 成功后清除

class ForgotPassword(models.Model):
    username = models.CharField(max_length=100)
    code = models.CharField(max_length=100)
    created = models.DateTimeField(auto_now_add=True)
