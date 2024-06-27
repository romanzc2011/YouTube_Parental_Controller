#ifndef YTUBE_CONTROLLER_H
#define YTUBE_CONTROLLER_H

#include <curl/curl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>

// Struct to hold data and command info
typedef struct {
    char *command;
    char *data;
} CommandData;

// Struct to hold data about Shared memory seg
typedef struct {
    size_t mem_size;
    void *shmaddr;
    void *data;
} SharedMemory;

// Struct to hold response data
typedef struct {
    char *memory;
    size_t size;
} MemoryStruct;

// YouTube Data API
typedef struct {
    char *http_type;
    char *url;
    char *api_filter;
    char *options;
    char *client_id;
    char *client_secret;
    char *refresh_token;
    char *grant_type;
    uint16_t http_code;
    char *http_message;
    
}YouTubeDataAPI;

extern CommandData *cmd_data;
extern SharedMemory *shared_memory;
extern YouTubeDataAPI *url_api;
extern MemoryStruct *memory_chunk;
extern char *curl_response;

key_t send_to_shared_mem(CommandData *cmd_data); // Sending data to shared memory
size_t get_data_size(CommandData *cmd_data);     // Get size of data
void create_process_exec_py(key_t shmkey);      // Create process to execute python script
void print_usage(FILE *stream, int exit_code);  // Print usage incase of error

// Handle memory alloc and exec python script in the case statements
key_t handle_mem_execpy(CommandData *cmd_data, char *arg, char *optarg); 
void *get_shared_memory(key_t shmkey);
void parse_response(char *json_string, char *anchor);

// YOUTUBE FUNCTIONS ########################################
char *list_all_subscribed_channels(const char *access_token);
char *get_access_token(const char *filename);
char *setup_curl(char *url, char *access_token, uint16_t http_code, char *error_message);

// MISC FUNCTIONS ###########################################
char *load_and_readf(char *file);
void *parse_data(char *json, char *root);
char *create_postfields(YouTubeDataAPI *url_api);
bool check_for_error(const char *response, YouTubeDataAPI *url_api);

#endif