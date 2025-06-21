'''import streamlit as st
import time
import re
from backend.Config import Config
from backend.storage import AzureStorage
from backend.oauth import OAuthService
from streamlit_cookies_manager import CookieManager

# Initialize services
config = Config()
storage = AzureStorage(config)
oauth_service = OAuthService(config)
cookies = CookieManager()

# Email validation regex
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

def validate_email(email):
    """Validate email format"""
    return re.match(EMAIL_REGEX, email)

def handle_google_login():
    """Handle Google OAuth login"""
    try:
        auth_url = oauth_service.get_google_auth_url()
        st.session_state.oauth_state = "google"  # Store state for verification
        st.markdown(f'<a href="{auth_url}" target="_self">Continue with Google</a>', unsafe_allow_html=True)
    except Exception as e:
        st.error(f"Google login failed: {str(e)}")

def login_page():
    st.markdown("""
    <style>
    .login-container {
        max-width: 500px;
        margin: 0 auto;
        padding: 2rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .divider {
        display: flex;
        align-items: center;
        text-align: center;
        margin: 1rem 0;
        color: #777;
    }
    .divider::before, .divider::after {
        content: "";
        flex: 1;
        border-bottom: 1px solid #ddd;
    }
    .divider::before {
        margin-right: 1rem;
    }
    .divider::after {
        margin-left: 1rem;
    }
    </style>
    """, unsafe_allow_html=True)

    with st.container():
        st.markdown('<div class="login-container">', unsafe_allow_html=True)
        
        st.title("Login to Ring Expert")
        
        # Email input
        email = st.text_input("Email", placeholder="example@gmail.com", 
                            value=cookies.get("remembered_email", ""))
        
        # Password input
        password = st.text_input("Password", type="password", 
                               placeholder="**********")
        
        # Remember me & Forgot password
        col1, col2 = st.columns([1, 1])
        with col1:
            remember_me = st.checkbox("Remember me", value=bool(cookies.get("remembered_email")))
        with col2:
            if st.button("Forgot password?"):
                st.switch_page("pages/3_Forgot_Password.py")
        
        # Login button
        if st.button("Login", type="primary"):
            if not email or not password:
                st.error("Please enter both email and password")
            elif not validate_email(email):
                st.error("Please enter a valid email address")
            else:
                with st.spinner("Authenticating..."):
                    try:
                        user = storage.authenticate_user(email, password)
                        if user:
                            st.session_state.update({
                                "logged_in": True,
                                "user_id": user["user_id"],
                                "email": user["email"],
                                "username": user.get("username", ""),
                                "full_name": user.get("full_name", "")
                            })
                            
                            if remember_me:
                                cookies["remembered_email"] = email
                            else:
                                cookies["remembered_email"] = ""
                                
                            st.success("Login successful!")
                            time.sleep(1)
                            st.switch_page("pages/2_Chat.py")
                        else:
                            st.error("Invalid credentials")
                    except Exception as e:
                        st.error(f"Login failed: {str(e)}")
        
        # Divider
        st.markdown('<div class="divider">or</div>', unsafe_allow_html=True)
        
        # Google login button
        if st.button("Continue with Google", icon="🔒"):
            handle_google_login()
        
        st.markdown("Don't have an account? [Sign up here](#)", unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)

# Check if already logged in
if st.session_state.get("logged_in"):
    st.switch_page("pages/2_Chat.py")
else:
    login_page()'''