'''
Author: Roman Campbell
Name: YouTube Parental Controller
Description: Command line tool currently for linux OS to control children's
             access to specific channels. Plan is to have th ability to block
             access to channels you dont want your kids to view, allow the ones
             you do, list current subscriptions, etc using Google's YouTube Data API v3
             API calls written in Python and command line tool in C
'''

from systemd import journal

SHM_SIZE = 1024
URL = "https://www.googleapis.com/youtube/v3/"
API_REFERENCE = ['subscriptions','search']
SHMKEY = 1000
 
######################################################################
# FUNCTIONS
######################################################################



# Write to log to test execution of various code
def write_to_journal(message):
    journal.send(message)

# Pretty print json data
def pretty_print_json(data):
    print(json.dumps(data, indent=4, sort_keys=True))

# Define headers for api calls
def define_headers(credentials):
    headers = {
        'Authorization' : f'Bearer {credentials.token}'
    }
    return headers
    
######################################################################
# List all currently subscribed to channels ##########################
def list_all_subscribed_channels(youtube):
    request = youtube.subscriptions().list(
        part="snippet,contentDetails",
        mine=True,
        maxResults=50,
        order="alphabetical"
    )
    
    response = request.execute()
    send_to_shared_mem(response)
    
    while response:
        if 'nextPageToken' in response:
            request = youtube.subscriptions().list(
                part="snippet,conentDetails",
                mine=True,
                maxResults=50,
                pageToken=response['nextPageToken']
            )
            response = request.execute()
            send_to_shared_mem(response)
        else:
            break

# Get YouTube channel id by username
def get_channel_id(credentials, handle):
    url = "https://www.googleapis.com/youtube/v3/channels"
    params = {
        'forHandle' : handle,
        'part' : 'contentDetails'
    }
    headers = define_headers(credentials)
    
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f'Error: {response.status_code}')
        return None
