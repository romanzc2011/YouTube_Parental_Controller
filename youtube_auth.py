import json
import os
import json
import logging
import requests
import sysv_ipc as ipc

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

SHM_SIZE = 1024
SHMKEY = 1000

# Save path for credentials
save_path = os.path.expanduser('~/my_projects/youtube_creds')

# File to store token
SCOPES = ['https://www.googleapis.com/auth/youtube']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

# Join files to proper filepath
CREDENTIALS_FILE = os.path.join(save_path, 'credentials.json')
CLIENT_SECRET_FILE = os.path.join(save_path, 'client_secret.json')

def send_to_shared_mem(data):
    subscription_json = json.dumps(data)
    subscription_bytes = subscription_json.encode('utf-8')
    
    mem_size = len(subscription_bytes)
    memory = ipc.SharedMemory(SHMKEY, ipc.IPC_CREAT, size=mem_size)
    memory.write(subscription_bytes)

# Read shared memory key for retrieval later
def read_from_shared_mem(shmkey):
    try:
        # Convert the key to int
        shmkey = int(shmkey)
        
        # Attach to existing shared mem seg
        shm = ipc.SharedMemory(shmkey)
        shmemory = shm.read(SHM_SIZE)
        shm.detach()

        content = shmemory.decode('utf-8').strip('\x00')
        
        # Init command and data
        command = None
        data = None
        
        if(content.startswith('CMD:')):
            # Extract command from CMD: and data from DATA:
            command = content[4:].split(';', 1)[0]
            print("Command received: ", command)
            
        if(';DATA:' in content):
            data = content.split(';DATA:', 1)[1]
            print("Data: ", data)
        
        return command, data
            
    except ipc.ExistentialError as e:
        print(f"Error accessing shared memory: {e}")

        return None, None
    except Exception as e:
        print(f"An unexpected error has occured {e}")
        
        return None, None

def save_credentials(credentials):
    with open(CREDENTIALS_FILE, 'w') as token:
        token.write(credentials.to_json())
        
def load_credentials():
    if os.path.exists(CREDENTIALS_FILE) and os.path.getsize(CREDENTIALS_FILE) > 0:
        with open(CREDENTIALS_FILE, 'r') as token:
            return Credentials.from_authorized_user_file(CREDENTIALS_FILE, SCOPES)
    return None

# Get YouTube authenticated  
def get_authenticated_service():
    credentials = load_credentials()
    
    # Request or refresh if loaded credentials are bad
    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
            credentials = flow.run_local_server(port=0)
            save_credentials(credentials)
    return build(API_SERVICE_NAME, API_VERSION, credentials=credentials)
    
def get_access_token():
    credentials = load_credentials()
    
    # Check if the credentials are valid
    if credentials and credentials.valid:
        # Credentials are valid, return the token
        return credentials.token

    # Credentials are invalid or do not exist
    if credentials and credentials.expired and credentials.refresh_token:
        try:
            # Attempt to refresh the credentials
            credentials.refresh(Request())
            save_credentials(credentials)
            return credentials.token
        except Exception as e:
            # Refresh failed, log error and fall through to re-authentication
            print(f"Failed to refresh token, re-authenticating: {e}")

    # No valid credentials, start re-authentication
    print("Starting new authentication flow...")
    flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
    credentials = flow.run_local_server(port=0)
    save_credentials(credentials)
    return credentials.token

# Example usage
if __name__ == "__main__":
    token = get_access_token()

