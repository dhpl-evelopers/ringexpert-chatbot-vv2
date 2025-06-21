'''import re

def validate_email(email):
    """Validate email format using regex"""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password meets complexity requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number"
    if not any(char in "!@#$%^&*()-_=+" for char in password):
        return False, "Password must contain at least one special character"
    return True, ""'''