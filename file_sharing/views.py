import os
import uuid
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from django.contrib import messages
from django.http import FileResponse, HttpResponseForbidden
from django.utils import timezone
from django.conf import settings
from django.urls import reverse
from datetime import timedelta

from .models import EncryptedFile, SecureLink, OTPVerification, DownloadLog
from .forms import (
    UserRegistrationForm, FileUploadForm, SecureLinkForm, 
    EmailForm, OTPVerificationForm
)
from .utils.encryption import encrypt_file, decrypt_file
from .utils.otp import create_otp, send_otp_email, verify_otp

def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def register(request):
    """User registration view"""
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Registration successful!")
            return redirect('dashboard')
        else:
            messages.error(request, "Registration failed. Please correct the errors.")
    else:
        form = UserRegistrationForm()
    
    return render(request, 'file_sharing/register.html', {'form': form})

@login_required
def dashboard(request):
    """User dashboard view"""
    user_files = EncryptedFile.objects.filter(user=request.user).order_by('-upload_date')
    user_links = SecureLink.objects.filter(created_by=request.user).order_by('-created_at')
    
    context = {
        'user_files': user_files,
        'user_links': user_links,
    }
    
    return render(request, 'file_sharing/dashboard.html', context)

@login_required
def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']

            # Save the file temporarily
            temp_path = os.path.join(settings.MEDIA_ROOT, 'temp', uploaded_file.name)
            os.makedirs(os.path.dirname(temp_path), exist_ok=True)

            with open(temp_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)

            # Encrypt the file
            encrypted_path, encryption_key = encrypt_file(temp_path)

            # Generate a unique filename for storage
            encrypted_filename = f"{uuid.uuid4()}{os.path.splitext(uploaded_file.name)[1]}.encrypted"

            # Create the encrypted file record
            encrypted_file = EncryptedFile.objects.create(
                user=request.user,
                original_filename=uploaded_file.name,
                encrypted_filename=encrypted_filename,
                file_size=uploaded_file.size,
                file_type=uploaded_file.content_type,
                encryption_key=encryption_key
            )

            # Save the encrypted file to storage
            if 'USE_FILEBASE' in os.environ and os.environ['USE_FILEBASE'] == 'True':
                from django.core.files.storage import default_storage
                from django.core.files.base import ContentFile

                with open(encrypted_path, 'rb') as f:
                    default_storage.save(encrypted_filename, ContentFile(f.read()))
            else:
                # Move to final location
                final_path = os.path.join(settings.MEDIA_ROOT, 'uploads', encrypted_filename)
                os.makedirs(os.path.dirname(final_path), exist_ok=True)
                shutil.move(encrypted_path, final_path)

            # Clean up temporary files
            if os.path.exists(temp_path):
                os.remove(temp_path)
            if os.path.exists(encrypted_path) and encrypted_path != final_path:
                os.remove(encrypted_path)

            messages.success(request, "File uploaded and encrypted successfully!")
            return redirect('dashboard')
    else:
        form = FileUploadForm()

    return render(request, 'file_sharing/upload_file.html', {'form': form})
@login_required
def create_secure_link(request, file_id):
    """Create a secure download link for a file"""
    encrypted_file = get_object_or_404(EncryptedFile, id=file_id, user=request.user)
    
    if request.method == 'POST':
        form = SecureLinkForm(request.POST)
        if form.is_valid():
            expiry_hours = form.cleaned_data['expiry_hours']
            max_downloads = form.cleaned_data['max_downloads']
            
            # Create secure link
            secure_link = SecureLink(
                file=encrypted_file,
                created_by=request.user,
                expires_at=timezone.now() + timedelta(hours=expiry_hours),
                max_downloads=max_downloads
            )
            secure_link.save()
            
            messages.success(request, "Secure download link created successfully!")
            return redirect('dashboard')
    else:
        form = SecureLinkForm()
    
    return render(request, 'file_sharing/create_link.html', {
        'form': form,
        'file': encrypted_file
    })

def download_request(request, link_id):
    """Handle initial download request and email collection"""
    secure_link = get_object_or_404(SecureLink, id=link_id)
    
    # Check if link is expired or max downloads reached
    if secure_link.is_expired():
        return render(request, 'file_sharing/download_error.html', {
            'error': "This download link has expired or reached maximum download limit."
        })
    
    if request.method == 'POST':
        form = EmailForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            
            # Create OTP verification
            otp_verification = create_otp(secure_link, email)
            
            # Send OTP email
            if send_otp_email(otp_verification):
                messages.success(request, f"OTP sent to {email}. Please check your inbox.")
                return redirect('verify_otp', otp_id=otp_verification.id)
            else:
                messages.error(request, "Failed to send OTP. Please try again.")
    else:
        form = EmailForm()
    
    return render(request, 'file_sharing/download_request.html', {
        'form': form,
        'secure_link': secure_link
    })

def verify_otp_view(request, otp_id):
    """Verify OTP and process download"""
    otp_verification = get_object_or_404(OTPVerification, id=otp_id)
    secure_link = otp_verification.secure_link
    
    # Check if OTP is expired
    if otp_verification.is_expired():
        return render(request, 'file_sharing/download_error.html', {
            'error': "OTP has expired. Please request a new download link."
        })
    
    # Check if link is expired
    if secure_link.is_expired():
        return render(request, 'file_sharing/download_error.html', {
            'error': "This download link has expired or reached maximum download limit."
        })
    
    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            entered_otp = form.cleaned_data['otp_code']
            
            # Verify OTP
            if verify_otp(otp_verification, entered_otp):
                # Log download attempt
                DownloadLog.objects.create(
                    secure_link=secure_link,
                    email=otp_verification.email,
                    ip_address=get_client_ip(request),
                    is_successful=True,
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                # Increment download counter
                secure_link.current_downloads += 1
                secure_link.save()
                
                # Decrypt file for download
                encrypted_file_path = os.path.join(
                    settings.MEDIA_ROOT, 
                    'uploads', 
                    secure_link.file.encrypted_filename
                )
                
                decrypted_file_path = decrypt_file(
                    encrypted_file_path, 
                    secure_link.file.encryption_key
                )
                
                # Serve the file
                response = FileResponse(
                    open(decrypted_file_path, 'rb'),
                    as_attachment=True,
                    filename=secure_link.file.original_filename
                )
                
                # Schedule file deletion after response is sent
                # In a production environment, you would use a task queue for this
                # For simplicity, we'll rely on the OS to clean up temporary files
                
                return response
            else:
                # Log failed attempt
                DownloadLog.objects.create(
                    secure_link=secure_link,
                    email=otp_verification.email,
                    ip_address=get_client_ip(request),
                    is_successful=False,
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                messages.error(request, "Invalid OTP. Please try again.")
    else:
        form = OTPVerificationForm()
    
    return render(request, 'file_sharing/verify_otp.html', {
        'form': form,
        'otp_verification': otp_verification
    })

@login_required
def admin_dashboard(request):
    """Admin dashboard view"""
    if not request.user.is_staff:
        return HttpResponseForbidden("You don't have permission to access this page.")
    
    all_files = EncryptedFile.objects.all().order_by('-upload_date')
    all_links = SecureLink.objects.all().order_by('-created_at')
    all_downloads = DownloadLog.objects.all().order_by('-timestamp')
    
    # Group downloads by IP to detect suspicious activity
    ip_counts = {}
    for log in all_downloads:
        ip = log.ip_address
        if ip not in ip_counts:
            ip_counts[ip] = {'total': 0, 'failed': 0}
        
        ip_counts[ip]['total'] += 1
        if not log.is_successful:
            ip_counts[ip]['failed'] += 1
    
    # Identify suspicious IPs (more than 5 failed attempts)
    suspicious_ips = {ip: data for ip, data in ip_counts.items() if data['failed'] > 5}
    
    context = {
        'all_files': all_files,
        'all_links': all_links,
        'all_downloads': all_downloads,
        'suspicious_ips': suspicious_ips,
    }
    
    return render(request, 'file_sharing/admin_dashboard.html', context)
