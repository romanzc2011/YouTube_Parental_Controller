from ytube_parental_pyfunc import *
from youtube_auth import *

import argparse
import sys

'''
Valid Commands:
RELOGIN - all current saved credentials are expired, relogin with Google API

'''


if __name__ == "__main__":
    
    # Setup argument parser
    parser = argparse.ArgumentParser(description="YouTube Parental Controller")
    parser.add_argument('-a', action='store_true', help="Option a")
    parser.add_argument('-u', type=str, help='Username')
    parser.add_argument('shmkey', type=int, help='Shared memory key')
    
    # # Parse the args
    args = parser.parse_args()
    
    memory_arr = []
    
    # Get shmkey from args
    shmkey = args.shmkey
    
    # Get access to current memory segment for clearing data
    # (attaching here as well because cant access it from inside existing function)
    shm = ipc.SharedMemory(shmkey, size=SHM_SIZE)
    
    memory = read_from_shared_mem(shmkey)
    memory_arr.append(memory)
    
    shm.write(b'\x00' * SHM_SIZE, 0) # Clear current segment of memory
    shm.detach()
    
    print(memory)
    print(memory_arr)
    
    if memory_arr[0][0] == "RELOGIN":
        youtube = get_access_token()