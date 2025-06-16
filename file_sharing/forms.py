from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.validators import FileExtensionValidator
from django.conf import settings
from .models import EncryptedFile, SecureLink
import os

class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    
    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user

class FileUploadForm(forms.ModelForm):
    file = forms.FileField(
        validators=[
            FileExtensionValidator(
                allowed_extensions=[ext.strip('.') for ext in settings.ALLOWED_FILE_EXTENSIONS]
            )
        ]
    )
    
    class Meta:
        model = EncryptedFile
        fields = ('file',)
        
    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file:
            # Check file size
            if file.size > settings.MAX_UPLOAD_SIZE:
                raise forms.ValidationError(f"File size cannot exceed {settings.MAX_UPLOAD_SIZE/(1024*1024)}MB")
            
            # Check file type
            file_ext = os.path.splitext(file.name)[1].lower()
            if file_ext not in settings.ALLOWED_FILE_EXTENSIONS:
                raise forms.ValidationError(f"Unsupported file type. Allowed types: {', '.join(settings.ALLOWED_FILE_EXTENSIONS)}")
        
        return file

class SecureLinkForm(forms.ModelForm):
    expiry_hours = forms.IntegerField(min_value=1, max_value=168, initial=24, 
                                     help_text="Link expiry time in hours (1-168)")
    max_downloads = forms.IntegerField(min_value=1, max_value=100, initial=3,
                                      help_text="Maximum number of downloads allowed")
    
    class Meta:
        model = SecureLink
        fields = ('expiry_hours', 'max_downloads')

class EmailForm(forms.Form):
    email = forms.EmailField(label="Email Address", 
                            help_text="Enter your email to receive the download OTP")

class OTPVerificationForm(forms.Form):
    otp_code = forms.CharField(
        label="OTP Code",
        max_length=6,
        min_length=6,
        help_text="Enter the 6-digit code sent to your email",
        widget=forms.TextInput(attrs={'placeholder': '123456'})
    )
