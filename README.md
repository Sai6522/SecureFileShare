# SecureFileShare

A Django web application for secure file sharing with end-to-end encryption, time-limited download links, and OTP verification.

## Features

- **User Authentication**: Register, login, and logout using Django's built-in auth system
- **Secure File Upload**: 
  - Support for PDF, DOCX, JPG, PNG, MP4, and MP3 files
  - AES encryption of files before storage
  - File metadata stored in SQLite database
- **Secure Download Links**:
  - UUID-based links
  - Customizable expiration time
  - Download limits
- **OTP Verification**:
  - Email-based OTP delivery
  - 5-minute OTP expiration
  - Verification required before download
- **Security Logging**:
  - Download attempts logged with email, IP, timestamp
  - Admin dashboard with security alerts
- **Responsive UI**: Bootstrap-based responsive design

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/SecureFileShare.git
cd SecureFileShare
```

2. Create a virtual environment and install dependencies:
```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Create a `.env` file from the example:
```
cp .env.example .env
```

4. Edit the `.env` file with your settings:
```
# Generate a new secret key
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

5. Run migrations:
```
python manage.py migrate
```

6. Create a superuser:
```
python manage.py createsuperuser
```

7. Run the development server:
```
python manage.py runserver
```

## Usage

1. Register a new account or login with existing credentials
2. Upload files through the dashboard
3. Create secure download links with custom expiration and download limits
4. Share the generated links with recipients
5. Recipients will need to:
   - Enter their email address
   - Receive and verify an OTP
   - Download the file after verification

## Security Features

- Files are encrypted using AES-256 before storage
- Encryption keys are stored securely in the database
- Files are only decrypted temporarily for download
- OTP verification prevents unauthorized access
- All download attempts are logged for security monitoring
- Suspicious IP detection for multiple failed attempts

## Admin Dashboard

Access the admin dashboard at `/admin-dashboard/` (staff users only) to:
- View all uploaded files and download statistics
- Monitor secure links and their status
- Review download logs
- Identify suspicious IP addresses

## Environment Variables

- `SECRET_KEY`: Django secret key
- `DEBUG`: Debug mode (True/False)
- `ALLOWED_HOSTS`: Comma-separated list of allowed hosts
- `EMAIL_*`: Email configuration for OTP delivery
- `ENCRYPTION_KEY`: Master key for file encryption

## License

MIT License
