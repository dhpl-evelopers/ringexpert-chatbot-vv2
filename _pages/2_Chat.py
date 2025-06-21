'''import streamlit as st
from backend.Config import Config
from backend.storage import AzureStorage
from backend.azure_api import AZURE_OPENAI_ENDPOINT, API_KEY, API_VERSION
import requests
import json

# Initialize services
config = Config()
storage = AzureStorage(config)

# Custom CSS for the chat interface
st.markdown("""
<style>
/* Chat interface styles */
.chat-container {
    max-width: 800px;
    margin: 0 auto;
}

.chat-message {
    padding: 12px 16px;
    border-radius: 8px;
    margin-bottom: 8px;
    max-width: 70%;
}

.user-message {
    background-color: #f0f2f6;
    margin-left: auto;
    border-bottom-right-radius: 0;
}

.bot-message {
    background-color: #C4A76D;
    color: white;
    margin-right: auto;
    border-bottom-left-radius: 0;
}

.login-button {
    position: absolute;
    top: 10px;
    right: 10px;
}
</style>
""", unsafe_allow_html=True)

# Check if user is logged in
is_logged_in = st.session_state.get("logged_in", False)

# Add login/signup button in top right
if not is_logged_in:
    cols = st.columns([1, 1])
    with cols[1]:
        if st.button("Login / Sign Up"):
            st.switch_page("pages/1_Login.py")
else:
    cols = st.columns([1, 1])
    with cols[1]:
        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()

# Chat title
st.title("💍 Ring Expert Chatbot")

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat input
if prompt := st.chat_input("Ask me anything about rings..."):
    # Add user message to chat history
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Generate bot response
    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            try:
                # Prepare API request
                headers = {
                    "Content-Type": "application/json",
                    "api-key": API_KEY
                }
                
                data = {
                    "messages": [{"role": m["role"], "content": m["content"]} 
                                for m in st.session_state.messages],
                    "max_tokens": 200
                }
                
                # Call Azure OpenAI API
                response = requests.post(
                    f"{AZURE_OPENAI_ENDPOINT}?api-version={API_VERSION}",
                    headers=headers,
                    json=data
                )
                
                response_data = response.json()
                full_response = response_data['choices'][0]['message']['content']
                
                # Display and store bot response
                st.markdown(full_response)
                st.session_state.messages.append({"role": "assistant", "content": full_response})
                
                # Save chat history if logged in
                if is_logged_in:
                    storage.save_chat(st.session_state["user_id"], st.session_state.messages)
                    
            except Exception as e:
                st.error(f"Error generating response: {str(e)}")'''