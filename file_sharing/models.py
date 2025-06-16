import uuid
import os
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

class EncryptedFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='uploaded_files')
    original_filename = models.CharField(max_length=255)
    encrypted_filename = models.CharField(max_length=255)
    file_size = models.PositiveIntegerField()  # Size in bytes
    file_type = models.CharField(max_length=100)
    encryption_key = models.CharField(max_length=255)  # Store the encryption key
    upload_date = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.original_filename} ({self.id})"

class SecureLink(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE, related_name='secure_links')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_links')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    max_downloads = models.PositiveIntegerField(default=3)
    current_downloads = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    
    def is_expired(self):
        return timezone.now() > self.expires_at or self.current_downloads >= self.max_downloads
    
    def __str__(self):
        return f"Link for {self.file.original_filename} ({self.id})"

class OTPVerification(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    secure_link = models.ForeignKey(SecureLink, on_delete=models.CASCADE, related_name='otp_verifications')
    email = models.EmailField()
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_verified = models.BooleanField(default=False)
    verification_attempts = models.PositiveIntegerField(default=0)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=5)
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"OTP for {self.email} ({self.id})"

class DownloadLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    secure_link = models.ForeignKey(SecureLink, on_delete=models.CASCADE, related_name='download_logs')
    email = models.EmailField()
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_successful = models.BooleanField(default=False)
    user_agent = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f"Download by {self.email} at {self.timestamp}"
