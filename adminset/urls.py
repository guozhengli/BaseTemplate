from django.conf.urls import url
from django.contrib import admin
from django.conf.urls import patterns, include, url
from . import views

from django.conf.urls import url, include
#from rest_framework import routers, serializers, viewsets

#from adminset import restapi,rest_url


urlpatterns = [
    #url(r'^', include(rest_url)),
    url(r'error', views.error, name="error"),
    url(r'cas_login', views.cas_login, name="cas_login"),


    url(r'^roles/$', views.roles_list, name="roles_list"),
    url(r'del_roles/(?P<id>[\d]+)$', views.del_role, name="del_role"),
    url(r'add_role$', views.add_role, name="add_role"),

    url(r'^users/$', views.users_list, name="users_list"),
    url(r'add_user$', views.add_user, name="add_user"),
    url(r'del_user/(?P<id>[\d]+)$', views.del_user, name="del_user"),
    url(r'modify_user/(?P<id>[\d]+)$', views.modify_user, name="modify_user"),
    url(r'reset_password$', views.reset_password, name="reset_password"),
    url(r'get_roles', views.get_roles_from_department, name="get_roles_from_department"),

    url(r'^department/$', views.department_list, name="department_list"),
    url(r'add_department', views.add_department, name="add_department"),
    url(r'del_department/(?P<id>[\d]+)$', views.del_department, name="del_department"),
    url(r'modify_department/(?P<id>[\d]+)$', views.modify_department, name="modify_department"),

    url(r'role_prem/(?P<id>[\d]+)$', views.role_prem, name="role_prem"),
    url(r'login_back', views.login_back, name="login_back"),
    url(r'login', views.login, name="login"),
    url(r'news$', views.news, name="news"),

    url(r'forgotpassword/', views.forgotpassword, name="forgotpassword"),
    url(r'forgotpassworddo/', views.forgotpassworddo, name="forgot_password_do"),
    url(r'modify_password/', views.modify_password, name="modify_password"),

    url(r'documentation/', views.documentation, name="documentation"),
]
