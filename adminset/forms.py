# coding: utf-8
import logging
import random

from django import forms
from django.contrib import auth
from django.core.exceptions import ValidationError
from django.core.exceptions import NON_FIELD_ERRORS

from .models import Role, UserPro, ForgotPassword
from lib.helper import Mail, check_password

logger = logging.getLogger('django')


class RoleForm(forms.ModelForm):

    def __init__(self, *args, **kwargs):
        super(RoleForm, self).__init__(*args, **kwargs)
        for name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

    class Meta:
        model = Role
        fields = ('name', 'desc')
        widgets = {'desc': forms.Textarea(attrs={'cols': 50, 'rows': 8})}

    def clean_name(self):
        """
        不能为空
        """
        name = self.cleaned_data['name']
        if name == u'':
            raise forms.ValidationError("角色名不能为空")
        return name

class LoginForm(forms.Form):

    user = forms.CharField(label=u'用户名',max_length=100, error_messages = {'required': u"请输入用户名"})
    password = forms.CharField(label=u'密码', widget=forms.PasswordInput, error_messages = {'required': u"请输入密码"})

    def __init__(self,request ,*args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        self._request = request
        for name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'
        self._user = ''
        self._username = ''

    def clean(self):
        username = self.cleaned_data.get('user', '')
        password = self.cleaned_data.get('password', '')
        try:
            user = UserPro.objects.get(name=username)
        except:
            user = ""
        if user and not user.is_active:
            raise forms.ValidationError(u"用户禁用")

        user = auth.authenticate(name=username, password=password)
        if not user:
            raise forms.ValidationError(u"用户名或密码错误！")
        self._user = user
        return self.cleaned_data


class PwresetForm(forms.Form):
    username = forms.CharField(label=u'用户名', error_messages = {'required': u"请输入用户名"})
    email = forms.CharField(label=u'邮箱', error_messages = {'required': u"请输入邮箱"})

    def __init__(self, request, *args, **kwargs):
        super(PwresetForm, self).__init__(*args, **kwargs)
        self._request = request
        for name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

    def clean_username(self):
        username = self.cleaned_data.get("username", "")
        try:
            user = UserPro.objects.get(name=username)
            return username
        except:
            raise forms.ValidationError(u"不存在的用户！")

    def clean_email(self):
        username = self.cleaned_data.get("username", "")
        email = self.cleaned_data.get("email", "")

        if not email.endswith('@zgxcw.com'):
            raise forms.ValidationError(u"邮箱格式错误")

        try:
            user = UserPro.objects.get(name=username, email=email)
            return email
        except:
            raise forms.ValidationError(u"用户名和邮箱不匹配！")


    def save(self):
        email = self.cleaned_data.get("email", "")
        username = self.cleaned_data.get("username", "")

        x = random.sample("abcdefghijklmnopqrstuvwxyz1234567890", 8)
        password =  "zgxcw000" + "".join(x)
        urlcode = "%s://%s/adminset/forgotpassworddo/?code=%s".decode("utf8") % \
                  (self._request.META['wsgi.url_scheme'], self._request.META['HTTP_HOST'],password)

        content = u"""
        您在诸葛修车网运维平台中申请了重置密码。  <p>
        请点击连接重置密码 <a href="%s">%s</a> 。  <p>
        如有疑问请联系管理员。
        """  % (urlcode, urlcode)
        ncode = ForgotPassword(username=username, code=password)
        ncode.save()
        mail = Mail()
        ok = mail.send(email, u"诸葛修改车网--运维平台", content)
        return ok


class Pwreset_doForm(forms.Form):
    password1 = forms.CharField(label=u'新密码', widget=forms.PasswordInput)
    password2 = forms.CharField(label=u'重复新密码', widget=forms.PasswordInput)

    def __init__(self, username, *args, **kwargs):
        super(Pwreset_doForm, self).__init__(*args, **kwargs)
        self._username = username
        self.user = UserPro.objects.get(name=self._username)
        for name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

    def clean_password1(self):
        password1 = self.cleaned_data.get("password1", "")

        check_password(password1)

        return password1

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1", "")
        password2 = self.cleaned_data.get("password2", "")

        if password1 != password2:
            raise forms.ValidationError(u"验证失败！两个新密码不一致！")

        return password2

    def save(self):
        password = self.cleaned_data.get("password1", "")
        self.user.set_password(password)
        self.user.save()



class PasswordForm(forms.Form):

    password = forms.CharField(label=u'旧密码', widget=forms.PasswordInput, error_messages = {'required': u"请输入旧密码"})
    password1 = forms.CharField(label=u'新密码', widget=forms.PasswordInput, error_messages = {'required': u"请输入新密码"})
    password2 = forms.CharField(label=u'确认密码', widget=forms.PasswordInput, error_messages = {'required': u"请输入确认密码"})

    def __init__(self, request, *args, **kwargs):
        super(PasswordForm, self).__init__(*args, **kwargs)
        self._request = request
        self.username = self._request.session.get('user', '')
        self.user = UserPro.objects.get(name=self.username)
        for name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

    def clean_password(self):

        password = self.cleaned_data.get("password", '')
        user = auth.authenticate(name=self.username, password=password)
        if user is not None:
            return password
        else:
            raise forms.ValidationError(u"验证失败！旧密码错误！")

    def clean_password1(self):
        password = self.cleaned_data.get("password", "")
        password1 = self.cleaned_data.get("password1", "")

        # 不能为空密码
        check_password(password1)

        if password == password1:
            raise forms.ValidationError(u"新旧密码不能相同！")

        return password1

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1", "")
        password2 = self.cleaned_data.get("password2", "")

        if password1 != password2:
            raise forms.ValidationError(u"验证失败！两个新密码不一致！")

        # Always return the full collection of cleaned data.
        return password2

    def save(self):
        password = self.cleaned_data.get("password1", "")
        self.user.set_password(password)
        self.user.save()