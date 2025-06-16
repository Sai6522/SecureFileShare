import random
import string
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from ..models import OTPVerification

def generate_otp(length=6):
    """Generate a random OTP code of specified length"""
    return ''.join(random.choices(string.digits, k=length))

def create_otp(secure_link, email):
    """
    Create a new OTP verification record
    
    Args:
        secure_link: SecureLink instance
        email: Email address to send OTP to
        
    Returns:
        OTPVerification: The created OTP verification record
    """
    otp_code = generate_otp()
    expires_at = timezone.now() + timedelta(minutes=5)
    
    # Create OTP verification record
    otp_verification = OTPVerification.objects.create(
        secure_link=secure_link,
        email=email,
        otp_code=otp_code,
        expires_at=expires_at
    )
    
    return otp_verification

def send_otp_email(otp_verification):
    """
    Send OTP code to user's email
    
    Args:
        otp_verification: OTPVerification instance
        
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    subject = "Your Secure File Download OTP"
    message = f"""
    Hello,
    
    You have requested to download a secure file. Please use the following OTP code to verify your download:
    
    {otp_verification.otp_code}
    
    This code will expire in 5 minutes.
    
    If you did not request this download, please ignore this email.
    
    Regards,
    SecureFileShare Team
    """
    
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [otp_verification.email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending OTP email: {e}")
        return False

def verify_otp(otp_verification, entered_otp):
    """
    Verify an OTP code
    
    Args:
        otp_verification: OTPVerification instance
        entered_otp: OTP code entered by user
        
    Returns:
        bool: True if OTP is valid, False otherwise
    """
    # Check if OTP is expired
    if otp_verification.is_expired():
        return False
    
    # Check if OTP is correct
    if otp_verification.otp_code != entered_otp:
        # Increment verification attempts
        otp_verification.verification_attempts += 1
        otp_verification.save()
        return False
    
    # Mark OTP as verified
    otp_verification.is_verified = True
    otp_verification.save()
    
    return True
