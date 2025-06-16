# SecureFileShare - Updated Setup Instructions

This is an updated guide for setting up and running the SecureFileShare application with SQLite integration.

## Project Overview

SecureFileShare is a Django web application for secure file sharing with features like:
- End-to-end encryption of files
- Time-limited download links
- OTP verification for downloads
- Security logging

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/SecureFileShare.git
cd SecureFileShare
```

### 2. Set Up the Environment

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment Variables

The `.env` file has been pre-configured with development settings. For production, you should update:
- SECRET_KEY
- ENCRYPTION_KEY
- Email settings

### 4. Initialize the SQLite Database

```bash
# Run migrations to create SQLite database tables
python manage.py migrate

# Create a superuser for admin access
python manage.py createsuperuser
```

### 5. Run the Development Server

```bash
python manage.py runserver
```

The application will be accessible at http://127.0.0.1:8000/

## SQLite Integration

The project is already configured to use SQLite as its database backend. The database file is located at:
```
/path/to/SecureFileShare/db.sqlite3
```

### Checking SQLite Tables

To verify that the database tables have been created:

```bash
# Using SQLite CLI
sqlite3 db.sqlite3
.tables
.schema file_sharing_encryptedfile
.quit

# Using Django's dbshell
python manage.py dbshell
.tables
.quit

# Using Django's shell
python manage.py shell
```

```python
from django.db import connection
cursor = connection.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
for table in tables:
    print(table[0])
```

## Project Structure

The project uses the following models in SQLite:

1. **EncryptedFile**: Stores metadata about uploaded files
2. **SecureLink**: Manages download links
3. **OTPVerification**: Handles OTP verification
4. **DownloadLog**: Logs download attempts

## Troubleshooting

If you encounter the error "Invalid filter: 'add_class'", it means the django-widget-tweaks package is not installed or not added to INSTALLED_APPS. This has been fixed in the updated code.

## Security Considerations

1. **Encryption Key**: The ENCRYPTION_KEY in the .env file is critical for security. If lost, encrypted files cannot be recovered.
2. **Database Backup**: Regularly backup the SQLite database file (db.sqlite3) to prevent data loss.
3. **Production Deployment**: For production, consider:
   - Using a more robust database like PostgreSQL
   - Setting up proper email configuration for OTP delivery
   - Configuring HTTPS for secure communication
   - Setting DEBUG=False in the .env file

## License

MIT License
