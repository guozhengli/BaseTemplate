# coding: utf-8
import logging
from django import forms

logger = logging.getLogger('django')

class LoginForm(forms.ModelForm):

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        for name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

    class Meta:
        model = Role
        fields = ('name', 'password')
        widgets = {'password': forms.Textarea(attrs={'cols': 50, 'rows': 8})}

    def clean_name(self):
        """
        不能为空
        """
        name = self.cleaned_data['name']
        if name == u'':
            raise forms.ValidationError("角色名不能为空")
        return name

