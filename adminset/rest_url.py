#!/usr/bin/env python
#coding:utf8 by guozheng_li
from django.conf.urls import url, include
from rest_framework import routers, serializers, viewsets
from adminset import restapi,views


# Routers provide an easy way of automatically determining the URL conf.
'''
REST    URL配置
'''
router = routers.DefaultRouter()
router.register(r'users', restapi.UserViewSet)
router.register(r'service', restapi.ServiceViewSet)


urlpatterns = [
    url(r'^rest/', include(router.urls)),
    url(r'^service_list/',restapi.ServiceList ),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework'))
]