#include <cjson/cJSON.h>
#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include "../include/ytube_controller.h"
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SHM_SIZE    1024 // 1K shared memory segment

const char *program_name = NULL;
bool has_errors = false;
char *curl_response = NULL;

// ENVIRONMENT VARIABLES
char *client_id = NULL;
char *client_secret = NULL;
char *refresh_token = NULL;

CommandData *cmd_data;
SharedMemory *shared_memory = NULL;
YouTubeDataAPI *url_api = NULL;
MemoryStruct *memory_chunk = NULL;


// Create memory and pack up before sending to shared memory
key_t handle_mem_execpy(CommandData *cmd_data, char *arg, char *optarg)
{
    key_t shmkey = 0;
    cmd_data->command = arg;

    /* Some commands do not have an optarg, allow the NULL to prevent SIGSEGV */
    if(optarg != NULL) {
        cmd_data->data = malloc(strlen(optarg)+1);
        strcpy(cmd_data->data, optarg);
    } else {
        cmd_data->data = NULL;
    }

    shmkey = send_to_shared_mem(cmd_data);

    // Free data alloc if not null
    if(cmd_data->data != NULL) {
        free(cmd_data->data);
        free(cmd_data);
    }
    return shmkey;
}

// Get size of data
size_t get_data_size(CommandData *cmd_data)
{
    if(cmd_data != NULL) {
       
        size_t data_length = (cmd_data->data != NULL) ? strlen((char *)cmd_data->data) + 1 : 0;
        size_t command_length = (cmd_data->command != NULL) ? strlen((char *)cmd_data->command) + 1 : 0;

        return data_length + command_length;
    } else {
        return 0;
    }
}

/* Prints the usage information for this program to STREAM
   and exit the program with EXIT_CODE. Does not return*/
void print_usage(FILE *stream, int exit_code)
{
  fprintf(stream, "Usage: %s options [ inputfile ... ] \n", program_name);
  fprintf(stream,
	  " -h  --help             Display this usage information.\n "
	  "-o  --output filename  Write output to file\n"
	  " -l  --list-channels    Print out your subscribed channgels\n"
	  " -u  --username         Username to query on\n"
	  " -id --handle-id        Channels handle id to query on\n"
	  " -r  --remove-channel   Channel to remove\n"
      " -a  --add-channel      Channel to add\n"
      " -v  --verbose          Print verbose messages\n");
  exit (exit_code);
}

/* Display loading bar during command execution */
void loading_bar()
{
}


// ####################################################################################
// GET SHARED MEMORY
void *get_shared_memory(key_t shmkey)
{
    size_t data_size = 0;
    int shmid = shmget(shmkey, sizeof(SharedMemory), 0666);
    if(shmid == -1) {
        perror("shmget");
        exit(1);
    }

    shared_memory = (SharedMemory *)malloc(sizeof(SharedMemory));
    if(shared_memory == NULL) {
        perror("malloc");
        exit(1);
    }

    shared_memory->shmaddr = shmat(shmid, NULL, 0);
    if(shared_memory->shmaddr == (void *) -1) {
        perror("shmat");
        exit(1);
    }

    struct shmid_ds shminfo;
    shmctl(shmid, IPC_STAT, &shminfo);
    data_size = shminfo.shm_segsz;
    shared_memory->mem_size = data_size;

    // Allocate memory for shared_memory->data
    shared_memory->data = malloc(data_size);
    if(shared_memory->data == NULL) {
        perror("malloc");
        exit(1);
    }
    memcpy(shared_memory->data, shared_memory->shmaddr, data_size);

    return shared_memory->shmaddr;
}

// ####################################################################################
// PARSE THRU ERROR
/**
 * @brief Parse through callback from curl and print data HTTP error codes will be
 *      caught here and sent back to main.c usually to request a new token from YouTube
 *
 *
 * @param[in] *json_string, json data to parse through
 * @return Actual error/success code of the curl execution
 */
size_t parse_print_error(char *json_string)
{
    cJSON *json = cJSON_Parse(json_string);

    if(json == NULL) {
        printf("Error parsing JSON\n");
        exit(EXIT_FAILURE);
    }

    // Check if error has 401
    cJSON *error = cJSON_GetObjectItemCaseSensitive(json, "error");
    if(!cJSON_IsObject(error)) {
        cJSON_Delete(json);
        return;
    }

    cJSON *code = cJSON_GetObjectItemCaseSensitive(error, "code");

    if(cJSON_IsNumber(code) && code->valueint == 401) {
        printf("Error code 401 found: %d\n", code->valueint);
        return code->valueint;
    } else {
        return;
    }
    cJSON_Delete(json);
}

// ####################################################################################
// PARSE AND PRINT
/**
 * @brief Parse through callback from curl and print data HTTP error codes will be
 *      caught here and sent back to main.c usually to request a new token from YouTube
 *
 *
 * @param[in] *json_string, json data to parse through
 * @param[in] *anchor target section to parse on
 * @return Parsed json 
 */
void parse_response(char *json_string, char *anchor) 
{
    cJSON *root = cJSON_Parse(json_string);
    size_t code = 0;

    if (root == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }
        return;
    }

    // Ensure url_api is initialized
    if(url_api ==  NULL) {
        url_api = (YouTubeDataAPI *)malloc(sizeof(YouTubeDataAPI));
        if(url_api == NULL) {
            perror("Failed to allocate memory\n");
            exit(EXIT_FAILURE);
        }
    }

    // Catch error first
    code = parse_print_error(json_string);
    
    if(code == 401) {
        // go back to main program and request a new credential
        url_api->http_code = 401;
        cJSON_Delete(root);
        return;
    }

    // ANCHOR == ITEMS
    if(strcmp(&anchor, "items")) {
        // Get items array
        cJSON *items = cJSON_GetObjectItem(root, "items");
        int items_count = cJSON_GetArraySize(items);
        int line = 1;

        // Print out list in abc order.
        for(int i=0; i < items_count; i++)
        {
            cJSON *item = cJSON_GetArrayItem(items, i);
            cJSON *snippet = cJSON_GetObjectItem(item, "snippet");
            cJSON *title = cJSON_GetObjectItem(snippet, "title");

            // Print the title
            printf("Channel %d: ", line);
            for(char *ch = title->valuestring; *ch != '\0'; ++ch)
            {
                printf("%c", *ch);
            }
            printf("\n");
            line++;
        }
    }
    cJSON_Delete(root);
}

// ####################################################################################
// SEND TO SHARED MEM
key_t send_to_shared_mem(CommandData *cmd_data)
{
    // Command/data to be separated with their type CMD/DATA and ending with ;
    key_t shmkey = 0;
    int shmid = 0;
    char *shmaddr = NULL;
    size_t data_size = 0;
    
    // Make the key
    if((shmkey = ftok("main.c", 'R')) == -1) {
        perror("ftok error\n");
        exit(1);
    }

    // Connect and create the segment
    if((shmid = shmget(shmkey, SHM_SIZE, 0644 | IPC_CREAT)) == -1) {
        perror("shmget error\n");
        exit(1);
    }

    // Attach segment to get a pointer to it 
    shmaddr = shmat(shmid, (void *)0, 0);

    if(shmaddr == (void *)(-1)) {
        perror("shmat error\n");
        exit(1);
    }

    // Skip serialization if data is 0x0    
    if(cmd_data != NULL) {
        data_size = get_data_size(cmd_data);
    }

    // Check if shared mem size is enough
    if(data_size > SHM_SIZE) {
        fprintf(stderr, "Data size exceeds shared memory size\n");
        exit(EXIT_FAILURE);
    }
 
    // Copy data and command to shared memory if not null
    if(cmd_data->command != NULL) {
        // Use type indicators for better visualization 
        strcpy(shmaddr, "CMD:");
        strcat(shmaddr, cmd_data->command);
    }

    // Delimit each section with ; for easier parsing with python
    if(cmd_data->data != NULL) {
        strcat(shmaddr,";DATA:");
        strcat(shmaddr, cmd_data->data); // Copy data to memory addr 
    }
    
    // Detach the shared mem segment
    if(shmdt(shmaddr) == -1) {
        perror("shmdt error\n");
        exit(1);
    }
    return shmkey;
}

// ####################################################################################
// CREATE PROCESS EXEC PY
void create_process_exec_py(key_t shmkey)
{
    int status = 0;
    int key_length = 0;
    char *key_str = NULL;
    pid_t pid = 0;
    int pipefd[2];

    // Checking for pipe creation
    if(pipe(pipefd) == -1) {
        perror("pipe error\n");
        exit(EXIT_FAILURE);
    }

    pid = fork();

    if(pid < 0) {
        perror("fork failed...\n");
        exit(EXIT_FAILURE);
    } else if(pid == 0) {
        // Child process
        close(pipefd[1]); // Close write end of pipe

        // Calculate length of key string for memory allocation
        key_length = snprintf(NULL, 0, "%d", shmkey) + 1;
        key_str = malloc(key_length * sizeof(char));

        if(key_str == NULL) {
            perror("malloc failed\n");
            exit(EXIT_FAILURE);
        }

        // Read key string from pipe and close
        read(pipefd[0], key_str, key_length);
        close(pipefd[0]);

        // Execute python script and free key_str
        execlp("python3", "python3", "../youtube_parental_control.py", key_str, (char *)NULL);
        
        perror("execlp error\n");
        free(key_str);

        
        exit(EXIT_FAILURE);

    } else {
        // Parent process
        close(pipefd[0]);

        // Calc and allocate memory
        key_length = snprintf(NULL, 0, "%d", shmkey) + 1;
        key_str = malloc(key_length * sizeof(char));

        if(key_str == NULL) {
            fprintf(stderr, "malloc failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        snprintf(key_str, key_length, "%d", shmkey);
        write(pipefd[1], key_str, key_length);
        close(pipefd[1]);

        wait(&status);
        free(key_str);
    }
}

// ####################################################################################
// ####################################################################################
// YOUTUBE CALLER FUNCTIONS
// ####################################################################################
// ####################################################################################

// ####################################################################################
// GET ACCESS TOKEN
char *get_access_token(const char *filename)
{
    char buffer[256];
    char *access_token = NULL;
    char *token_buffer = NULL;
    char *file_contents = NULL;
    size_t file_size = 0;
    size_t buffer_size = 256;
    size_t new_length = 0;
    size_t token_buffer_size = 0;

    // Open file to read credentials.json if it comes back 401, request new token
    file_contents = load_and_readf(filename);

    cJSON *json = cJSON_Parse(file_contents);
    if(json == NULL) 
    {
        fprintf(stderr, "Error parsing JSON\n");
        free(file_contents);
        exit(EXIT_FAILURE);
    }

    cJSON *token = cJSON_GetObjectItemCaseSensitive(json, "token");

    if(token == NULL || !cJSON_IsString(token)) {
        fprintf(stderr, "Access token not found in credentials\n");
        cJSON_Delete(json);
        free(file_contents);
        exit(EXIT_FAILURE);
    }

    access_token = strdup(token->valuestring);

    // Clean up
    cJSON_Delete(json);
    free(file_contents);

    return access_token;
}

// ####################################################################################
// WRITE MEMORY CALLBACK
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    MemoryStruct *mem = (MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);

    if(ptr == NULL) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// ####################################################################################
// LIST ALL SUBSCRIBED CHANNELS
char *list_all_subscribed_channels(const char *access_token)
{
    char *url = NULL;
    size_t url_length = 0;

    // Allocate memory for YouTubeDataAPI
    if(url_api ==  NULL) {
        url_api = (YouTubeDataAPI *)malloc(sizeof(YouTubeDataAPI));
        if(url_api == NULL) {
            perror("Failed to allocate memory\n");
            exit(EXIT_FAILURE);
    }
  }

    url_api->url = "https://www.googleapis.com/youtube/v3/";
    url_api->api_filter = "subscriptions?";
    url_api->options = "part=snippet,contentDetails&mine=true&maxResults=50&order=alphabetical";
    
    // Length of url_api for memory allocation
    url_length = strlen(url_api->url) + strlen(url_api->api_filter) + strlen(url_api->options) + 1;
    url = malloc(url_length * sizeof(char));

    if(url == NULL) {
        perror("Failed to allocate memory for url\n");
        exit(EXIT_FAILURE);
    }

    // Concat full url together
    snprintf(url, url_length, "%s%s%s", url_api->url, url_api->api_filter, url_api->options);    

    curl_response = setup_curl(url, access_token, NULL, NULL);
    if(curl_response == NULL) {
        perror("Failed to get response from setup_curl\n");
        free(url);
        return NULL;
    }
    
    free(url);
    return curl_response;
}

// ####################################################################################
// LOAD AND READ
char *load_and_readf(char *file)
{
    char *buffer = 0;
    char *end = 0;
    size_t length = 0;
    FILE *fd = fopen(file, "r");

    if(fd) {
        fseek(fd, 0, SEEK_END);
        length = ftell(fd);
        fseek(fd, 0, SEEK_SET);

        buffer = (char *)malloc(length + 1);

        if(buffer) {
            fread(buffer, 1, length, fd);
            buffer[length] = '\0';
        }
        fclose(fd);
    }

    if(fd == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    if(buffer == NULL) {
        perror("Memory allocation failure\n");
        exit(EXIT_FAILURE);
    }

    // Trim trailing whitespace
    end = buffer + length - 1;
    while(end > buffer && isspace((unsigned char)*end))
    {
        end--;
    }
    end[1] = '\0';

    return buffer;
}

char *create_postfields(YouTubeDataAPI *url_api)
{
    // Calculate total length
    size_t postfields_length = strlen(url_api->client_id) +
                               strlen(url_api->client_secret) +
                               strlen(url_api->refresh_token) +
                               strlen(url_api->grant_type) + 1;

    // Allocate memory for postfields
    char *postfields = (char *)malloc(postfields_length * sizeof(char));
    if(postfields == NULL) {
        perror("Failed to allocate memory\n");
        exit(EXIT_FAILURE);
    }

    // Concatenate the strings into postfields
    snprintf(postfields, postfields_length, "%s%s%s%s",
             url_api->client_id, url_api->client_secret,
             url_api->refresh_token, url_api->grant_type);

    return postfields;
}

char *setup_curl(char *url, char *access_token, uint16_t http_code, char *error_message) {
    CURL *curl = NULL;
    char *postfields = NULL;
    CURLcode res;
    struct curl_slist *headers = NULL;
    MemoryStruct memory_chunk;
    size_t postfields_length = 0;

    memory_chunk.memory = malloc(1); // Initial allocation
    memory_chunk.size = 0;

    // Initialize CURL
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    if(!curl) {
        fprintf(stderr, "curl_easy_init() failed\n");
        free(memory_chunk.memory);
        curl_global_cleanup();
        return NULL;
    }

    // Check for HTTP 401 error code, inital attempt to get new token, maybe need to login again
    if (http_code == 401) {
        
        client_id = getenv("CLIENT_ID");
        client_secret = getenv("CLIENT_SECRET");
        refresh_token = getenv("REFRESH_TOKEN");

        // URL for POST request
        url_api->url = "https://oauth2.googleapis.com/token";
        url_api->client_id = client_id;
        url_api->client_secret = client_secret;
        url_api->refresh_token = refresh_token;
        url_api->grant_type = "&grant_type=refresh_token";

        postfields_length = strlen(url_api->client_id) + 
                            strlen(url_api->client_secret) + 
                            strlen(url_api->refresh_token) + 
                            strlen(url_api->grant_type) + 1;

        postfields = (char *)malloc(postfields_length);
        if (postfields == NULL) {
            perror("Failed to allocate memory\n");
            exit(EXIT_FAILURE);
        }
        snprintf(postfields, postfields_length, "%s%s%s%s", url_api->client_id, 
                url_api->client_secret, url_api->refresh_token, url_api->grant_type);

        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

        curl_easy_setopt(curl, CURLOPT_URL, url_api->url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&memory_chunk);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        free(postfields);

        return memory_chunk.memory;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);

    // Set Auth header with access token
    char auth_header[256];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", access_token);
    headers = curl_slist_append(headers, auth_header);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&memory_chunk);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        free(memory_chunk.memory);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        curl_global_cleanup();
        return NULL;
    } else {
        printf("%lu bytes retrieved\n", (unsigned long)memory_chunk.size);
    }

    // Clean up
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    curl_global_cleanup();

    return memory_chunk.memory; // return the retrieved data
}

// Function to check for error response instead of expected response
bool check_for_error(const char *response, YouTubeDataAPI *url_api)
{
    cJSON *json = cJSON_Parse(response);
    cJSON *code = NULL;
    cJSON *message = NULL;
    cJSON *error = NULL;

    // Check if url_api has allocated memory first
    if(url_api ==  NULL) {
        url_api = (YouTubeDataAPI *)malloc(sizeof(YouTubeDataAPI));
        if(url_api == NULL) {
            perror("Failed to allocate memory\n");
            exit(EXIT_FAILURE);
    }
  }

    if(json == NULL) {
        printf("Error parsing JSON\n");
        return;
    }

    // Check if the "error" field is present
    error = cJSON_GetObjectItemCaseSensitive(json, "error");
    if(error) {
        has_errors = true;

        // Extract error details
        code = cJSON_GetObjectItemCaseSensitive(error, "code");

        // if there is an http error code convert it to int, same with message except string
        if(code) {
            url_api->http_code = code->valueint;
        }

        message = cJSON_GetObjectItemCaseSensitive(error, "message");
        if(message) {
            url_api->http_message = message->valuestring;
        }

        // Checking for invalid_grant
        if(!code || !message) {
            message = error->valuestring;
            url_api->http_message = message;
            printf("%s\n", message);
            return true;
        }

        cJSON_Delete(json);
        return true;
    }

    cJSON_Delete(json);
    return false;
}