#!/usr/bin/env python
#coding:utf8 by guozheng_li
from adminset.models import UserPro as User
from rest_framework import routers, serializers, viewsets
from adminset.serializers import UserSerializer,ServiceSerializer

from rest_framework import status
from rest_framework import  permissions
from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
from .serializers import UserSerializer,ServiceSerializer
#REST认证装饰器
from .permission_rest import rest_permission,users,validation

# ViewSets define the view behavior.
class UserViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

#ModelViewSet
class ServiceViewSet(viewsets.ReadOnlyModelViewSet):
    pass

@api_view(['GET'])
@permission_classes((permissions.AllowAny,))
def ServiceList(request,):
    '''
    自定义
    :param request:
    :return:
    '''
    if request.method == 'GET':
        pass

    elif request.method == 'POST':
        pass