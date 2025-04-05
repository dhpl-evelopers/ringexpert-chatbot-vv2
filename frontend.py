import streamlit as st
import bcrypt
import os
import requests
from dotenv import load_dotenv
from azure.storage.blob import BlobServiceClient
import json
import uuid
from datetime import datetime
from authlib.integrations.requests_client import OAuth2Session
import urllib.parse
import logging
import re
from PIL import Image
import base64
from io import BytesIO

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="RINGEXPERT", 
    page_icon="💍", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- SESSION STATE INITIALIZATION ---
if "logged_in" not in st.session_state:
    st.session_state.update({
        "logged_in": False,
        "username": None,
        "email": None,
        "user_id": None,
        "oauth_provider": None,
        "show_register": False,
        "messages": [],
        "full_name": None,
        "show_login": False,
        "show_quick_prompts": True,
        "active_tab": "chat"
    })

# --- CONFIGURATION ---
class Config:
    # Azure Storage Configuration
    AZURE_CONNECTION_STRING = os.getenv("AZURE_CONNECTION_STRING")
    if not AZURE_CONNECTION_STRING:
        raise ValueError("Azure Storage connection string is not configured in environment variables")
    
    CONTAINER_NAME = os.getenv("AZURE_CONTAINER_NAME", "bot-data")
    
    # OAuth Configuration
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8501")
    
    # API Configuration
    CHAT_API_URL = os.getenv("CHAT_API_URL", "https://ringexpert-backend.azurewebsites.net/ask")
    BOT_AVATAR_URL = os.getenv("BOT_AVATAR_URL", "https://i.imgur.com/JQ6W0nD.png")
    LOGO_URL = os.getenv("LOGO_URL", "https://ringsandi.com/wp-content/uploads/2023/11/ringsandi-logo.png")
    IMAGE_API_URL = os.getenv("IMAGE_API_URL", "https://ringexpert-backend.azurewebsites.net/generate-image")
    
    QUICK_PROMPTS = [
        "What is Ringsandi?",
        "Where are you located?",
        "What will I get different at RINGS & I?",
        "What is the main difference between 14K and 18K gold?",
        "What is the main difference between platinum and gold in terms of purity?"
    ]



# Validate required configurations
if not Config.AZURE_CONNECTION_STRING:
    raise ValueError("Azure Storage connection string is not configured")
if not Config.GOOGLE_CLIENT_ID or not Config.GOOGLE_CLIENT_SECRET:
    logger.warning("Google OAuth credentials not fully configured")

# --- AZURE STORAGE SERVICE ---
class AzureStorage:
    def __init__(self):
        self._initialize_storage()
        
    def _initialize_storage(self):
        """Initialize and validate Azure Storage connection"""
        try:
            logger.info("Initializing Azure Storage connection")
            self.blob_service = BlobServiceClient.from_connection_string(Config.AZURE_CONNECTION_STRING)
            self.container = self.blob_service.get_container_client(Config.CONTAINER_NAME)
            
            if not self.container.exists():
                logger.info(f"Creating container: {Config.CONTAINER_NAME}")
                self.container.create_container()
                self._initialize_folder_structure()
                
            logger.info("Azure Storage initialized successfully")
            
        except Exception as e:
            logger.error(f"Storage initialization failed: {str(e)}")
            st.error("Failed to initialize storage system. Please contact support.")
            st.stop()
    
    def _initialize_folder_structure(self):
        """Create required directory structure"""
        try:
            self.upload_blob("users/.placeholder", "")
            self.upload_blob("chats/.placeholder", "")
            logger.info("Created storage folder structure")
        except Exception as e:
            logger.warning(f"Couldn't create folders: {str(e)}")
    
    def upload_blob(self, blob_name, data):
        """Secure blob upload with validation"""
        try:
            blob = self.container.get_blob_client(blob_name)
            if isinstance(data, (dict, list)):
                data = json.dumps(data, indent=2)
            blob.upload_blob(data, overwrite=True)
            return True
        except Exception as e:
            logger.error(f"Upload failed for {blob_name}: {str(e)}")
            return False
    
    def download_blob(self, blob_name):
        """Secure blob download with validation"""
        try:
            blob = self.container.get_blob_client(blob_name)
            if blob.exists():
                return blob.download_blob().readall()
            return None
        except Exception as e:
            logger.error(f"Download failed for {blob_name}: {str(e)}")
            return None
    
    def blob_exists(self, blob_name):
        try:
            return self.container.get_blob_client(blob_name).exists()
        except Exception as e:
            logger.error(f"Existence check failed for {blob_name}: {str(e)}")
            return False
    
    def user_exists(self, email):
        return self.blob_exists(f"users/{email}.json")
    
    def create_user(self, email, password=None, username=None, provider=None, **kwargs):
        user_data = {
            "user_id": str(uuid.uuid4()),
            "email": email,
            "username": username or email.split('@')[0],
            "password": self._hash_password(password or "oauth_user"),
            "provider": provider,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": datetime.utcnow().isoformat(),
            **kwargs
        }
        
        if self.upload_blob(f"users/{email}.json", user_data):
            return user_data
        return None
    
    def get_user(self, email):
        data = self.download_blob(f"users/{email}.json")
        return json.loads(data) if data else None
    
    def authenticate_user(self, email, password):
        user = self.get_user(email)
        if user and self._check_password(password, user["password"]):
            return user
        return None
    
    def save_chat(self, user_id, messages):
        if messages:  # Only save if there are messages
            return self.upload_blob(f"chats/{user_id}.json", messages)
        return False
    
    def load_chat(self, user_id):
        data = self.download_blob(f"chats/{user_id}.json")
        return json.loads(data) if data else []
    
    def _hash_password(self, password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    def _check_password(self, input_password, hashed_password):
        try:
            return bcrypt.checkpw(input_password.encode(), hashed_password.encode())
        except:
            return False

# Initialize storage
storage = AzureStorage()

# --- OAUTH SERVICE ---
class OAuthService:
    @staticmethod
    def get_google_auth_url():
        client = OAuth2Session(
            Config.GOOGLE_CLIENT_ID,
            Config.GOOGLE_CLIENT_SECRET,
            redirect_uri=Config.REDIRECT_URI
        )
        return client.create_authorization_url(
            "https://accounts.google.com/o/oauth2/auth",
            scope="openid email profile",
            access_type="offline",
            prompt="consent",
            state="google"
        )[0]
    
    @staticmethod
    def handle_google_callback(code):
        try:
            client = OAuth2Session(
                Config.GOOGLE_CLIENT_ID,
                Config.GOOGLE_CLIENT_SECRET,
                redirect_uri=Config.REDIRECT_URI
            )
            
            token = client.fetch_token(
                "https://oauth2.googleapis.com/token",
                code=code,
                redirect_uri=Config.REDIRECT_URI
            )
            
            user_info = client.get("https://www.googleapis.com/oauth2/v3/userinfo").json()
            return user_info
        except Exception as e:
            logger.error(f"OAuth callback failed: {str(e)}")
            return None

# --- HELPER FUNCTIONS ---
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
    return True, ""

def send_chat_message(prompt):
    """Send message to the right backend: image generation or Q&A"""
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.session_state.show_quick_prompts = False

    try:
        # Very specific trigger: only route to image if prompt contains keywords like 'generate ring'
        if "generate" in prompt.lower() and "ring" in prompt.lower():
            response = requests.post(
                Config.IMAGE_API_URL,
                json={"prompt": prompt},
                timeout=30
            )
            response.raise_for_status()
            image_url = response.json().get("image_url", "")

            if image_url and image_url.startswith("http"):
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": f"Here's your AI-generated ring:\n\n![Generated Ring]({image_url})"
                })
            else:
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": "Sorry, the image could not be generated."
                })
        else:
            # Default: route to the Q&A endpoint
            response = requests.post(
                Config.CHAT_API_URL,
                json={"question": prompt},
                timeout=15
            )
            response.raise_for_status()
            answer = response.json().get("answer", "I couldn't process that question.")
            st.session_state.messages.append({"role": "assistant", "content": answer})

    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {str(e)}")
        st.session_state.messages.append({
            "role": "assistant",
            "content": "Sorry, I'm having trouble connecting to the service."
        })

    if st.session_state.user_id:
        storage.save_chat(st.session_state.user_id, st.session_state.messages)

    st.rerun()

# --- AUTHENTICATION UI ---
def show_auth_ui():
    """Unified login/signup interface with tabs"""
    with st.container():
        # Header with logo
        st.markdown(f"""
            <div class="auth-container">
                <div class="auth-header">
                    <img src="{Config.LOGO_URL}" width="80" style="margin-bottom: 1rem;">
                    <div class="auth-title">Welcome to RINGS & I</div>
                    <div class="auth-subtitle">Your personal AI RingExpert</div>
                </div>
        """, unsafe_allow_html=True)

        # Create tabs for Login and Sign Up
        tab1, tab2 = st.tabs(["Sign In", "Create Account"])
        
        with tab1:
            show_login_form()
        
        with tab2:
            show_register_form()

        # Social login divider (shown below both forms)
        st.markdown(f"""
            <div class="divider">or continue with</div>
            <a href="{OAuthService.get_google_auth_url()}" class="oauth-btn">
                <img src="https://upload.wikimedia.org/wikipedia/commons/5/53/Google_%22G%22_Logo.svg" width="20" height="20" style="vertical-align:middle; margin-right:10px;">
                <span>Continue with Google</span>
            </a>
        """, unsafe_allow_html=True)

def show_login_form():
    """Login form (for tab)"""
    with st.form(key="login_form"):
        email = st.text_input("Email Address", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        
        col1, col2 = st.columns([1, 2])
        with col1:
            login_btn = st.form_submit_button("Sign In", type="primary", use_container_width=True)
        with col2:
            forgot_btn = st.form_submit_button("Forgot Password?", use_container_width=True)
        
        if login_btn:
            if not email or not password:
                st.error("Please enter both email and password")
            elif not validate_email(email):
                st.error("Please enter a valid email address")
            else:
                user = storage.authenticate_user(email, password)
                if user:
                    complete_login(user)
                else:
                    st.error("Invalid credentials")
        
        if forgot_btn:
            st.info("Please contact support to reset your password")

def show_register_form():
    """Registration form (for tab)"""
    with st.form(key="register_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            first_name = st.text_input("First Name*")
            email = st.text_input("Email Address*")
            
        with col2:
            last_name = st.text_input("Last Name")
            username = st.text_input("Username*")
        
        password = st.text_input("Password*", type="password")
        confirm_password = st.text_input("Confirm Password*", type="password")
        agree = st.checkbox("I agree to Terms & Privacy Policy*", value=False)
        
        if st.form_submit_button("Create Account", type="primary"):
            # Validation logic
            if not all([first_name, email, username, password, confirm_password, agree]):
                st.error("Please fill all required fields (*)")
            elif not validate_email(email):
                st.error("Invalid email format")
            elif password != confirm_password:
                st.error("Passwords don't match!")
            else:
                valid, msg = validate_password(password)
                if not valid:
                    st.error(msg)
                elif storage.user_exists(email):
                    st.error("Email already registered!")
                else:
                    user_data = storage.create_user(
                        email=email,
                        password=password,
                        username=username,
                        provider="email",
                        first_name=first_name,
                        last_name=last_name,
                        full_name=f"{first_name} {last_name}".strip()
                    )
                    if user_data:
                        st.success("Account created! Please sign in.")
                        st.session_state.show_register = False
                        st.session_state.show_login = True
                        st.rerun()

def complete_login(user_data):
    """Complete login process and set session state"""
    st.session_state.update({
        "logged_in": True,
        "user_id": user_data["user_id"],
        "email": user_data["email"],
        "username": user_data["username"],
        "full_name": user_data.get("full_name", user_data["username"]),
        "oauth_provider": user_data.get("provider"),
        "messages": storage.load_chat(user_data["user_id"]) or [],
        "show_login": False,
        "show_quick_prompts": True,
        "active_tab": "chat"
    })
    
    # Update last login time
    try:
        user_data["last_login"] = datetime.utcnow().isoformat()
        storage.upload_blob(f"users/{user_data['email']}.json", user_data)
    except Exception as e:
        logger.error(f"Error updating last login: {str(e)}")
    
    st.rerun()

def logout():
    """Handle logout process"""
    if st.session_state.user_id and st.session_state.messages:
        # Save chat history before logging out
        storage.save_chat(st.session_state.user_id, st.session_state.messages)
    
    # Reset session state
    st.session_state.update({
        "logged_in": False,
        "user_id": None,
        "email": None,
        "username": None,
        "full_name": None,
        "oauth_provider": None,
        "messages": [],
        "show_login": False,
        "show_quick_prompts": True,
        "active_tab": "chat"
    })
    st.rerun()

def show_chat_ui():
    # Add auth button at top right
    if not st.session_state.logged_in:
        # Create a container for the auth button at top right
        auth_container = st.container()
        with auth_container:
            col1, col2 = st.columns([5, 1])
            with col2:
                if st.button("Sign Up / Login", key="top_right_auth_btn", type="primary"):
                    st.session_state.show_login = True
                    st.rerun()

    # Create two columns - sidebar (left) and main chat (right)
    with st.sidebar:
        # Logo and title
        st.markdown(f"""
            <div style="text-align: center; margin-bottom: 2rem;">
                <img src="{Config.LOGO_URL}" style="max-width: 200px; height: auto;">
                <div style="font-size: 1.3rem; margin: 20px 0; color: #C4A76D; font-weight: 600; letter-spacing: 0.5px;">
                    RINGS & I AI RingExpert
                </div>
            </div>
        """, unsafe_allow_html=True)
        
        # Quick Prompts section
        st.markdown("""
            <div style="margin-bottom: 2rem;">
                <div style="font-size: 1.2rem; margin-bottom: 20px; padding-bottom: 10px; 
                            border-bottom: 1px solid rgba(196, 167, 109, 0.3); color: #924c26; font-weight: 500;">
                    Quick Prompts
                </div>
        """, unsafe_allow_html=True)
        
        for prompt in Config.QUICK_PROMPTS:
            if st.button(
                prompt,
                key=f"quick_prompt_{prompt}",
                use_container_width=True,
                help=f"Click to ask: {prompt}"
            ):
                send_chat_message(prompt)
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        # User info section if logged in
        if st.session_state.logged_in:
            st.markdown(f"""
                <div style="margin-top: 2rem; padding: 1rem; background-color: white; border-radius: 6px;">
                    <div style="font-weight: 600; margin-bottom: 0.5rem;">Logged in as:</div>
                    <div>{st.session_state.full_name or st.session_state.username}</div>
                    <div style="font-size: 0.9rem; color: #666;">{st.session_state.email}</div>
                </div>
            """, unsafe_allow_html=True)
            
            if st.button("Logout", use_container_width=True):
                logout()

    # Main chat area
    with st.container():
        # Chat header
        st.markdown("""
            <div style="text-align: center; margin-bottom: 2rem;">
                <h1 style="color: #C4A76D; margin-bottom: 8px; font-size: 2rem; font-weight: 600; letter-spacing: 0.5px;">
                    Welcome to RINGS & I!
                </h1>
                <p style="font-size: 1.1rem; color: #333333; margin: 0;">
                     The RingExpert is here to help. Ask away!
                </p>
            </div>
        """, unsafe_allow_html=True)
        
        # Welcome message if no messages yet
        if len(st.session_state.messages) == 0:
            st.markdown("""
                <div style="padding: 16px 20px; margin-bottom: 16px; max-width: 75%; border-radius: 8px; 
                        line-height: 1.6; font-size: 1.1rem; box-shadow: 0 2px 8px rgba(0,0,0,0.05);
                        background-color: white; border-left: 4px solid #C4A76D; border-bottom-left-radius: 0;
                        animation: fadeIn 0.4s ease;">
                    <div style="font-weight: 600; color: #C4A76D; margin-bottom: 8px; font-size: 1.1rem; 
                                display: flex; align-items: center; gap: 8px;">
                        <span style="display: inline-block; width: 8px; height: 8px; background-color: #C4A76D; border-radius: 50%;"></span>
                        AI RingExpert
                    </div>
                    Welcome to RINGS & I! I'm your AI RingExpert here to assist with any questions about diamond rings.
                </div>
            """, unsafe_allow_html=True)
        
        # Display chat messages
        for msg in st.session_state.messages:
            if msg["role"] == "user":
                st.markdown(f"""
                    <div style="padding: 16px 20px; margin-bottom: 16px; max-width: 75%; margin-left: auto;
                            border-radius: 8px; line-height: 1.6; font-size: 1.1rem; 
                            background-color: white; border: 1px solid rgba(196, 167, 109, 0.2);
                            border-bottom-right-radius: 0;">
                        {msg["content"]}
                    </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                    <div style="padding: 16px 20px; margin-bottom: 16px; max-width: 75%; margin-right: auto;
                            border-radius: 8px; line-height: 1.6; font-size: 1.1rem; box-shadow: 0 2px 8px rgba(0,0,0,0.05);
                            background-color: white; border-left: 4px solid #C4A76D; border-bottom-left-radius: 0;">
                        <div style="font-weight: 600; color: #C4A76D; margin-bottom: 8px; font-size: 1.1rem; 
                                display: flex; align-items: center; gap: 8px;">
                            <span style="display: inline-block; width: 8px; height: 8px; background-color: #C4A76D; border-radius: 50%;"></span>
                            AI RingExpert
                        </div>
                        {msg["content"]}
                    </div>
                """, unsafe_allow_html=True)
        
        # Chat input
        if prompt := st.chat_input("Ask..."):
            send_chat_message(prompt)
        
        # Footer
        st.markdown("""
            <div style="text-align: center; margin-top: 1rem; padding: 15px 20px; font-size: 0.9rem; 
                    border-top: 1px solid rgba(196, 167, 109, 0.2); color: #333333;">
                Powered by RINGS & I 
                <br>
                <a href="https://ringsandi.com" target="_blank" style="color: #C4A76D; text-decoration: none; 
                        font-weight: 500; transition: color 0.3s;">Visit ringsandi.com</a>
            </div>
        """, unsafe_allow_html=True)

# --- MAIN APP FLOW ---
def handle_oauth_callback():
    """Handle OAuth callback after authentication"""
    params = st.query_params.to_dict()
    if params.get("code") and params.get("state") == "google":
        user_info = OAuthService.handle_google_callback(params["code"])
        if user_info:
            email = user_info.get("email")
            if email:
                # Check if user exists or create new
                user = storage.get_user(email)
                if not user:
                    # Create new user with Google info
                    user = storage.create_user(
                        email=email,
                        provider="google",
                        username=email.split('@')[0],
                        full_name=user_info.get("name", ""),
                        first_name=user_info.get("given_name", ""),
                        last_name=user_info.get("family_name", "")
                    )
                
                if user:
                    complete_login(user)
                    st.query_params.clear()

# Handle custom messages from frontend
if "quick_prompt" in st.session_state:
    send_chat_message(st.session_state.quick_prompt["data"])
    del st.session_state.quick_prompt

handle_oauth_callback()

# Main app logic
if st.session_state.get("show_login"):
    show_auth_ui()
elif st.session_state.logged_in:
    show_chat_ui()
else:
    show_chat_ui()

# --- CSS STYLING ---
st.markdown("""
    <style>
:root {
    --font: "oregon-ldo-medium", sans-serif;
    --white: #FAFAFA;
    --black: #1c1c1c;
    --light-gray: #A5A5A5;
    --dark-gray: #777777;
    --brown: #924c26;
    --brown-gradient: linear-gradient(to right, #924c26 0%, #ce875e 49%, #924c26 100%);
    --border-radius: 20px;
}

/* Base app styling */
.stApp {
    background-color: var(--white);
    color: var(--black);
    font-family: var(--font);
}

/* Chat screen header or welcome box (apply manually to content if needed) */
.chat-header {
    background: var(--brown-gradient);
    color: var(--white);
    padding: 1.5rem;
    border-radius: var(--border-radius);
    text-align: center;
    font-size: 1.4rem;
    font-weight: bold;
}

/* Sidebar styling */
.st-emotion-cache-6qob1r {
    background-color: var(--white);
    border-right: 1px solid rgba(0, 0, 0, 0.05);
    font-family: var(--font);
}

/* Chat input styling */
.stChatInput {
    background-color: var(--white);
    border-top: 0px solid rgba(0, 0, 0, 0.05);
    padding: 1rem;
}

/* Chat Input Field */
.stTextInput > div > div > input {
    border: 2px solid #ce875e !important;  /* default border */
    background-color: #FAFAFA;
    color: #1c1c1c;
    font-family: "oregon-ldo-medium", sans-serif;
    padding: 14px 18px;
    border-radius: 20px;
    font-size: 16px;
    transition: all 0.3s ease;
}

/* Chat Input Field on focus */
.stTextInput > div > div > input:focus {
    border: 2px solid #924c26 !important;  /* your brand brown */
    box-shadow: 0 0 0 2px rgba(146, 76, 38, 0.15);
    outline: none;
}

/* Button styling */
.stButton > button {
    background-color: var(--brown);
    color: var(--white);
    font-family: var(--font);
    border-radius: var(--border-radius);
    font-weight: 500;
    padding: 12px 24px;
    transition: all 0.3s ease;
}

.stButton > button:hover {
    background-color: #ce875e;
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(146, 76, 38, 0.2);
}

/* Divider style */
.divider {
    color: var(--dark-gray);
    margin: 1.5rem 0;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
    display: flex;
    align-items: center;
}

.divider::before, .divider::after {
    content: "";
    flex: 1;
    border-bottom: 1px solid var(--light-gray);
}

/* Auth / Welcome card */
.auth-container {
    background-color: var(--white);
    border: 1px solid rgba(0, 0, 0, 0.08);
    border-radius: var(--border-radius);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.06);
    padding: 2rem;
    max-width: 480px;
    margin: 2rem auto;
    font-family: var(--font);
}

/* Auth headers */
.auth-title {
    font-size: 26px;
    color: var(--brown);
    font-weight: bold;
    margin-bottom: 0.5rem;
    text-align: center;
}

.auth-subtitle {
    color: var(--dark-gray);
    font-size: 14px;
    letter-spacing: 0.5px;
    text-align: center;
}

/* OAuth Button */
.oauth-btn {
    background-color: var(--white);
    color: var(--black);
    border: 1px solid var(--light-gray);
    border-radius: var(--border-radius);
    padding: 12px;
    font-weight: 500;
    font-family: var(--font);
    text-align: center;
    text-decoration: none;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.3s ease;
}

.oauth-btn:hover {
    border-color: var(--brown);
    transform: translateY(-2px);
    box-shadow: 0 4px 10px rgba(146, 76, 38, 0.1);
}

/* Responsive design */
@media (max-width: 768px) {
    .auth-container {
        padding: 1.5rem;
        margin: 1rem;
    }

    .auth-title {
        font-size: 22px;
    }
}
</style>
""", unsafe_allow_html=True)