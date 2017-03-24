from django.core.management.base import BaseCommand
from adminset.models import Permissions, UserPro, Role, Department

class Command(BaseCommand):
    help = u'初始化系统中权限，如果权限已存在操作'
    print 'test projects'