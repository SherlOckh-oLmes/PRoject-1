import json
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.views import View
from django.contrib.auth.models import User
from pydantic import validate_email
from youtify import settings
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.core.mail import send_mail
from django.utils.encoding import force_bytes


def default(request):
    return render(request, "player.html")

class EmailValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        email = data.get('email')
        if not validate_email(email):
            return JsonResponse({'email_error': 'Email is invalid'}, status=400)
        if User.objects.filter(email=email).exists():
            return JsonResponse({'email_error': 'Sorry, email in use. Choose another one.'}, status=409)
        return JsonResponse({'email_valid': True})

class UsernameValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        username = data.get('username')
        if not str(username).isalnum():
            return JsonResponse({'username_error': 'Username should only contain alphanumeric characters'}, status=400)
        if User.objects.filter(username=username).exists():
            return JsonResponse({'username_error': 'Sorry, username in use. Choose another one.'}, status=409)
        return JsonResponse({'username_valid': True})
class VerificationView(View):
    def get(self, request, uidb64, token):
        try:
             id = force_text(urlsafe_base64_decode(uidb64))
             user = User.objects.get(pk=id)

             if not account_activation_token.check_token(user, token):
                 return redirect('login' + '?message=' + 'User already activated')

             if user.is_active:
                return redirect('login')
             user.is_active = True
             user.save()        
             messages.success(request, 'Account activated successfully')
             return redirect('login')

        except Exception:
             pass

        return redirect('login')

def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm-password')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
        elif User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
        elif password != confirm_password:
            messages.error(request, "Passwords do not match.")
        else:
            try:
                user = User.objects.create_user(username=username, email=email, password=password)
                messages.success(request, "Account created successfully.")

                # Send welcome email
                subject = "Welcome to Youtify"
                message = f"Hi {user.username}, welcome to Youtify! We are glad to have you."
                from_email = settings.EMAIL_HOST_USER
                to_list = [user.email]
                send_mail(subject, message, from_email, to_list, fail_silently=False)

                return redirect('authentication:login')
            except ValidationError as e:
                messages.error(request, f"Error creating account: {e}")

    return render(request, 'signup.html')
def password_recovery(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)
            # Generate token and uid for the password reset link
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # Prepare the email
            subject = "Password Recovery"
            message = render_to_string('password_reset_email.html', {
                'user': user,
                'uid': uid,
                'token': token,
                'protocol': request.scheme,
                'domain': request.get_host(),
            })
            from_email = settings.EMAIL_HOST_USER
            to_list = [user.email]
            send_mail(subject, message, from_email, to_list, fail_silently=False)

            messages.success(request, "A password recovery email has been sent.")
            return redirect('authentication:password_reset_done')

        except User.DoesNotExist:
            messages.error(request, "No account associated with this email.")

    return render(request, 'password_reset_form.html')
def login_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            auth_login(request, user)
            
            return redirect('authentication:default')
        else:
            messages.error(request, "Invalid username or password")
    
    return render(request, 'login.html')

def logout_view(request):
    if request.method == 'POST':
        auth_logout(request)
        messages.success(request, 'You have been logged out.')
        return redirect('authentication:login')
    return redirect('authentication:default')
