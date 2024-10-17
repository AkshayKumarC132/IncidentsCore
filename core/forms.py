# forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import UserProfile

class UserProfileRegistrationForm(UserCreationForm):
    class Meta:
        model = UserProfile
        fields = ('username', 'email', 'name', 'password1', 'password2')
    
    # You can add additional validation or customization here if needed.


class UserProfileLoginForm(AuthenticationForm):
    class Meta:
        model = UserProfile
        fields = ('username', 'password')
