# forms.py
import base64
import hashlib
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .models import ProfileUser
from captcha.fields import ReCaptchaField
from captcha.widgets import ReCaptchaV3
from django_ratelimit.decorators import ratelimit

class RegisterForm(UserCreationForm):
    cid = forms.CharField(max_length=20, label=('เลขประจำตัวประชาชน'), widget=forms.TextInput(attrs={'placeholder': ('กรอกเลขประจำตัวประชาชน 13 หลัก')}))
    phone = forms.CharField(max_length=20, label=('เบอร์โทรศัพท์มือถือ'), widget=forms.TextInput(attrs={'placeholder': ('กรอกเบอร์โทรศัพท์มือถือ 10 หลัก')}))
    first_name = forms.CharField(max_length=150, label=('ชื่อตามบัตรประชาชน'), widget=forms.TextInput(attrs={'placeholder': ('ชื่อตามบัตรประชาชน ไม่กรอกคำนำหน้าชื่อ')}))
    last_name = forms.CharField(max_length=150, label=('นามสกุลตามบัตรประชาชน'), widget=forms.TextInput(attrs={'placeholder': ('นามสกุลตามบัตรประชาชน')}))
    captcha = ReCaptchaField(widget=ReCaptchaV3)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'first_name', 'last_name', 'cid', 'phone']

    def save(self, commit=True):
        user = super(RegisterForm, self).save(commit=False)

        # encrypt fields using Base64+SHA256
        user.first_name = base64.b64encode(hashlib.sha256(self.cleaned_data['first_name'].encode()).digest()).decode()
        user.last_name = base64.b64encode(hashlib.sha256(self.cleaned_data['last_name'].encode()).digest()).decode()
        profile_user = ProfileUser(cid=base64.b64encode(hashlib.sha256(self.cleaned_data['cid'].encode()).digest()).decode(),
                                   phone=base64.b64encode(hashlib.sha256(self.cleaned_data['phone'].encode()).digest()).decode())

        if commit:
            user.save()
            profile_user.user = user
            profile_user.save()

        return user

@ratelimit(key='user', rate='5/h', block=True)
class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}))
    
    def __init__(self, *args, **kwargs):
        super().__init__( *args, **kwargs)