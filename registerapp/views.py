from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login as auth_login, logout, authenticate
from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.contrib.auth.decorators import login_required
from django.conf import settings
from captcha.fields import ReCaptchaField
from django_ratelimit.decorators import ratelimit
from ipware import get_client_ip
from .forms import RegisterForm, LoginForm
from .models import ProfileUser


@ratelimit(key='ip', rate='10/m', block=True)  # limit to 10 requests per hour per IP address
def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            if settings.DEBUG:
                # if running in debug mode, don't check the reCAPTCHA
                pass
            else:
                # check the reCAPTCHA
                captcha_response = request.POST.get('g-recaptcha-response')
                recaptcha_field = ReCaptchaField()
                recaptcha_field.clean(captcha_response)

            form.save()
            return redirect('/')
    else:
        form = RegisterForm()
        client_ip, _ = get_client_ip(request)
        context = {
            'form': form,
            'client_ip': client_ip,
        }
    
    return render(request, 'registerapp/register.html', context)

@login_required
@ratelimit(key='ip', rate='5/m', block=True)  # limit to 5 requests per minute per IP address
def register_detail(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    profile = get_object_or_404(ProfileUser, user=user)
    
    context = {
        'user': user,
        'profile': profile,
    }
    
    return render(request, 'register_detail.html', context)

@ratelimit(key='user', rate='3/m', block=True)
@ratelimit(key='ip', rate='10/m', block=True)
def login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST, request=request)
        if form.is_valid():
            # Validate the reCAPTCHA field
            if form.cleaned_data.get('captcha'):
                # ReCAPTCHA validation passed
                username = form.cleaned_data.get('username')
                password = form.cleaned_data.get('password')
                user = authenticate(request, username=username, password=password)
                if user is not None:
                    auth_login(request, user)
                    # Check for 2FA via email
                    email = user.email
                    if email:
                        # Generate and send OTP via email
                        otp = get_random_string(length=6, allowed_chars='0123456789')
                        cache.set(email, otp, timeout=300)  # Store OTP in cache for 5 minutes
                        subject = 'Login OTP for your account'
                        message = f'Your one time password is {otp}. This OTP is valid for 5 minutes only.'
                        from_email = settings.DEFAULT_FROM_EMAIL
                        recipient_list = [email]
                        send_mail(subject, message, from_email, recipient_list, fail_silently=False)
                        return redirect('verify_otp')
                    else:
                        return redirect('home')
                else:
                    messages.error(request, 'Invalid username or password')
            else:
                # ReCAPTCHA validation failed
                messages.error(request, 'Invalid reCAPTCHA. Please try again.')
        else:
            messages.error(request, 'Error input. Please try again.')
            # Handle form validation errors
    else:
        form = LoginForm(request=request)
    context = {
        'form': form,
    }
    return render(request, 'login.html', context)

@login_required
def verify_otp(request):
    if request.method == 'POST':
        otp = request.POST.get('otp')
        email = request.user.email
        cached_otp = cache.get(email)
        if cached_otp == otp:
            # OTP is correct
            cache.delete(email)  # Remove the OTP from cache
            return redirect('home')
        else:
            # OTP is incorrect
            messages.error(request, 'Invalid OTP')
            return redirect('verify_otp')
    else:
        return render(request, 'verify_otp.html')

def logout_view(request):
    logout(request)
    return redirect('login')