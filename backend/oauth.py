# backend/oauth.py
'''from authlib.integrations.requests_client import OAuth2Session
from datetime import datetime, timedelta
import logging
from urllib.parse import urlparse, parse_qs
import re

logger = logging.getLogger(__name__)

class OAuthService:
    def __init__(self, config):
        self.config = config
    
    def get_google_auth_url(self):
        """Generate Google OAuth authorization URL"""
        try:
            client = OAuth2Session(
                self.config.GOOGLE_CLIENT_ID,
                self.config.GOOGLE_CLIENT_SECRET,
                redirect_uri=self.config.REDIRECT_URI
            )
            auth_url, _ = client.create_authorization_url(
                "https://accounts.google.com/o/oauth2/auth",
                scope="openid email profile",
                access_type="offline",
                prompt="consent",
                state="google"
            )
            return auth_url
        except Exception as e:
            logger.error(f"Failed to generate Google auth URL: {str(e)}")
            raise Exception("Could not generate authentication URL")

    def handle_google_callback(self, code):
        """Handle Google OAuth callback and fetch user info"""
        try:
            client = OAuth2Session(
                self.config.GOOGLE_CLIENT_ID,
                self.config.GOOGLE_CLIENT_SECRET,
                redirect_uri=self.config.REDIRECT_URI
            )
            
            token = client.fetch_token(
                "https://oauth2.googleapis.com/token",
                code=code,
                authorization_response=self.config.REDIRECT_URI,
                client_secret=self.config.GOOGLE_CLIENT_SECRET
            )
            
            user_info = client.get("https://www.googleapis.com/oauth2/v3/userinfo").json()
            
            if 'expires_in' in token:
                user_info['token_expires_at'] = datetime.utcnow() + timedelta(seconds=token['expires_in'])
            
            return user_info
            
        except Exception as e:
            logger.error(f"OAuth callback failed: {str(e)}")
            return None

    def parse_authorization_response(self, redirect_response):
        """Parse the authorization response from the redirect URL"""
        try:
            parsed = urlparse(redirect_response)
            query_params = parse_qs(parsed.query)
            
            if 'error' in query_params:
                error = query_params['error'][0]
                logger.error(f"OAuth error: {error}")
                return None
                
            if 'code' not in query_params:
                logger.error("No authorization code in response")
                return None
                
            return query_params['code'][0]
            
        except Exception as e:
            logger.error(f"Failed to parse authorization response: {str(e)}")
            return None

    def validate_state(self, received_state, original_state="google"):
        """Validate the state parameter for CSRF protection"""
        return received_state == original_state

    def refresh_token(self, refresh_token):
        """Refresh an expired access token"""
        try:
            client = OAuth2Session(
                self.config.GOOGLE_CLIENT_ID,
                self.config.GOOGLE_CLIENT_SECRET,
                redirect_uri=self.config.REDIRECT_URI
            )
            
            new_token = client.refresh_token(
                "https://oauth2.googleapis.com/token",
                refresh_token=refresh_token,
                client_id=self.config.GOOGLE_CLIENT_ID,
                client_secret=self.config.GOOGLE_CLIENT_SECRET
            )
            
            return new_token
            
        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
            return None

# Email and password validation functions
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