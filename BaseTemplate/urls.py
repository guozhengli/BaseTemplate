from django.conf.urls import url, include
from adminset import views as adminset_views

urlpatterns = [
    url(r'^$', adminset_views.index, name="index"),
    url(r'error', adminset_views.error, name="error"),
    url(r'login/', adminset_views.login, name="login"),
    url(r'logout/', adminset_views.logout, name="logout"),
    url(r'^adminset/', include('adminset.urls')),
]
