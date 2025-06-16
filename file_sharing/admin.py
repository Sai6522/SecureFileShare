from django.contrib import admin
from .models import EncryptedFile, SecureLink, OTPVerification, DownloadLog

@admin.register(EncryptedFile)
class EncryptedFileAdmin(admin.ModelAdmin):
    list_display = ('original_filename', 'user', 'file_size', 'file_type', 'upload_date')
    list_filter = ('file_type', 'upload_date')
    search_fields = ('original_filename', 'user__username')
    readonly_fields = ('id', 'upload_date')

@admin.register(SecureLink)
class SecureLinkAdmin(admin.ModelAdmin):
    list_display = ('id', 'file', 'created_by', 'created_at', 'expires_at', 
                   'max_downloads', 'current_downloads', 'is_active')
    list_filter = ('is_active', 'created_at')
    search_fields = ('file__original_filename', 'created_by__username')
    readonly_fields = ('id', 'created_at')

@admin.register(OTPVerification)
class OTPVerificationAdmin(admin.ModelAdmin):
    list_display = ('email', 'secure_link', 'created_at', 'expires_at', 
                   'is_verified', 'verification_attempts')
    list_filter = ('is_verified', 'created_at')
    search_fields = ('email', 'secure_link__file__original_filename')
    readonly_fields = ('id', 'created_at')

@admin.register(DownloadLog)
class DownloadLogAdmin(admin.ModelAdmin):
    list_display = ('email', 'ip_address', 'timestamp', 'is_successful')
    list_filter = ('is_successful', 'timestamp')
    search_fields = ('email', 'ip_address', 'secure_link__file__original_filename')
    readonly_fields = ('id', 'timestamp')
