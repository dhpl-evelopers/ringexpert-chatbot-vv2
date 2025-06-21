'''import streamlit as st
from backend.Config import Config
from backend.storage import AzureStorage
from backend.oauth import OAuthService

def main():
    # Initialize session state
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    # Initialize services
    config = Config()
    storage = AzureStorage(config)
    oauth_service = OAuthService(config)
    
    # Clean page switching without sidebar
    if not st.session_state.logged_in:
        st.switch_page("pages/1_Login.py")
    else:
        st.switch_page("pages/2_Chat.py")

if __name__ == "__main__":
    main()'''