import bcrypt
import json
import uuid
from datetime import datetime
from azure.storage.blob import BlobServiceClient
import logging

logger = logging.getLogger(__name__)

class AzureStorage:
    def __init__(self, config):
        self.config = config
        self._initialize_storage()
        
    def _initialize_storage(self):
        """Initialize and validate Azure Storage connection"""
        try:
            logger.info("Initializing Azure Storage connection")
            self.blob_service = BlobServiceClient.from_connection_string(self.config.AZURE_CONNECTION_STRING)
            self.container = self.blob_service.get_container_client(self.config.CONTAINER_NAME)
            
            if not self.container.exists():
                logger.info(f"Creating container: {self.config.CONTAINER_NAME}")
                self.container.create_container()
                self._initialize_folder_structure()
                
            logger.info("Azure Storage initialized successfully")
            
        except Exception as e:
            logger.error(f"Storage initialization failed: {str(e)}")
            raise Exception("Failed to initialize storage system. Please contact support.")

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
        return self.upload_blob(f"chats/{user_id}.json", messages)
    
    def load_chat(self, user_id):
        data = self.download_blob(f"chats/{user_id}.json")
        return json.loads(data) if data else []
    
    def _hash_password(self, password):
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    def _check_password(self, input_password, hashed_password):
        """Verify password using bcrypt"""
        try:
            return bcrypt.checkpw(input_password.encode(), hashed_password.encode())
        except Exception as e:
            logger.error(f"Password check failed: {str(e)}")
            return False