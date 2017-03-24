#!/usr/bin/env python
#coding=utf-8
from django.core.management.base import BaseCommand
from adminset.models import Permissions, UserPro, Role, Department
#from deployment.models import TaskStatusType


class Command(BaseCommand):
    help = u'初始化系统中权限，如果权限已存在操作'
    def handle(self, *args, **options):
        '''
        初始化权限
        第一列： 父权限， -1，便是没有父权限
        第二列： 权限名
        第三列： 权限描述
        '''

        print "##########          创建权限          ##########"

        prems = [
            (-1, 'can_role_manager', u'角色管理'),
            (-1, 'can_user_manager', u'用户管理'),
            (-1, 'can_department_manager', u'部门管理'),
            (-1, 'can_hosts_manager', u'主机管理'),
            ('can_hosts_manager', 'can_add_host_manager', u'增加主机'),
            ('can_hosts_manager', 'can_modify_host_manager', u'修改主机'),
            ('can_hosts_manager', 'can_delete_host_manager', u'删除主机'),
            ('can_hosts_manager', 'can_batch_import_host_manager', u'批量导入'),
        ]

        def print_prem(res):
            if res[1]:
                print "%50s :权限不存在,已创建!" % res[0]
            else:
                print "%50s :权限已存在,不在创建!" % res[0]

        for prem in prems:
            if prem[0] == -1 or prem[0] == '-1':
                tmp = Permissions.objects.get_or_create(parentid=-1, name=prem[1], desc=prem[2])
                print_prem(tmp)
            else:
                parent = Permissions.objects.get(name=prem[0])
                tmp = Permissions.objects.get_or_create(parentid=parent.id, name=prem[1], desc=prem[2])
                print_prem(tmp)

        print "##########      创建管理员用户         #########"

        root = UserPro.objects.filter(name='root')
        if len(root) == 0:
            root = UserPro.objects.create_superuser(email='pulishroot@zgxcw.com', username='root', password='zgtx123.com',aliasname=u'超级管理员')
            print "用户root已创建"
        else:
            print "用户root已存在，不再创建"

        root = UserPro.objects.get(name='root')

        print "##########      创建管理员角色           ###########"
        role = Role.objects.filter(name='admin')
        if len(role) == 0:
            role = Role(
                name='admin',
                desc=u'系统管理员'
            )
            role.save()
            print "系统管理员角色已创建"
        else:
            print "系统管理员角色已存在，不再创建"

        print "##########      创建默认的空角色           ###########"
        role = Role.objects.filter(name='anonymousrole')
        if len(role) == 0:
            role = Role(
                name='anonymousrole',
                desc=u'匿名角色'
            )
            role.save()
            print "匿名角色已创建"
        else:
            print "匿名角色已存在，不再创建"

        print "##########      创建匿名的空部门           ###########"
        department = Department.objects.filter(name='anonymousdepartment')
        if len(department) == 0:
            department = Department(
                name='anonymousdepartment',
            )
            department.save()
            role = Role.objects.filter(name='anonymousrole')
            department.add_role(role[0])

            print "匿名的空部门已创建"
        else:
            print "匿名的空部门已存在，不再创建"


        print "###########      开始授权            ###########"

        role = Role.objects.get(name='admin')
        prems = Permissions.objects.all()
        for prem in prems:
            role.add_premission(prem)

        root.role_set.add(role)