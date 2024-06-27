#include <cjson/cJSON.h>
#include <getopt.h>
#include "../include/ytube_controller.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> // for pid_t
#include <sys/wait.h>  // for wait
#include <time.h>
#include <unistd.h> // for fork

int main(int argc, char *argv[])
{
  clock_t start, end;
  double cpu_time_used;
  int next_option = 0;
  int verbose = 0;
  int *list_data = 0;
  size_t data_size = 0;
  char *output_filename = NULL;
  char *handle_id = NULL;
  char *username = NULL;
  char *add_channel_cmd = NULL;
  char *access_token = NULL;
  bool has_errors = false;
  key_t shmkey = 0;
  char *url = NULL;
  char *curl_response = NULL;
  CURL *curl = NULL;
  size_t url_length = 0;
  uint16_t http_code = 0;
  CURLcode res;
  MemoryStruct *memory_chunk = NULL;
  YouTubeDataAPI *url_api = NULL;
  CommandData *cmd_data = NULL;
  
  // #####################################################################################
  // Start run timer
  // #####################################################################################
  start = clock();
  

  // Valid short option letters
  const char *short_options = "o:a:i:u:hrlv";
  const char *program_name = NULL;
  const char *cred_filename = "../../youtube_creds/credentials.json";
  //SharedMemory shared_memory;

  program_name = argv[0];

  // Allocate memory for structs
  if (url_api == NULL) {
    url_api = (YouTubeDataAPI *)malloc(sizeof(YouTubeDataAPI));
    if (url_api == NULL) {
        perror("Failed to allocate memory for url_api\n");
        exit(EXIT_FAILURE);
    }
  }

  if (cmd_data == NULL) {
    cmd_data = (CommandData *)malloc(sizeof(CommandData));
    if (cmd_data == NULL) {
        perror("Failed to allocate memory for cmd_data\n");
        exit(EXIT_FAILURE);
    }
  }

  if(memory_chunk == NULL) {
    memory_chunk = (MemoryStruct *)malloc(sizeof(MemoryStruct));
    if(memory_chunk == NULL) {
      perror("Failed to allocate memory for memory_chunk\n");
      exit(EXIT_FAILURE);
    }
  }

  // Init structs
  cmd_data->command = NULL;
  cmd_data->data = NULL;
  url_api->http_code = NULL;
  url_api->http_message = NULL;

  /* List valid short options letters  */
  const struct option long_options[] = {
        {"help",           no_argument,       NULL, 'h'},
        {"output-file",    required_argument, NULL, 'o'},
        {"add-channel",    required_argument, NULL, 'a'},
        {"username",       required_argument, NULL, 'u'},
        {"remove-channel", no_argument,       NULL, 'r'},
        {"list-channels",  no_argument,       NULL, 'l'},
        {"verbose",        no_argument,       NULL, 'v'},
        {NULL,             0,                 NULL,  0}
    };

  if(argc < 2) {
    print_usage(stdout, 0);
  }

  do {

    next_option = getopt_long(argc, argv, short_options, long_options, NULL);

    if(next_option == -1) break;

    switch(next_option)
      {
        case 'h': // Help print out
          print_usage(stdout, 0);
          break;

        case 'l': // --list-channels
          // Construct URL for listing channels
          access_token = get_access_token(cred_filename);
          
          // There was a failure in getting access token
          if(!access_token) {
            fprintf(stderr, "Failed to get access token\n");
            free(url_api);
            exit(EXIT_FAILURE);
          }

          curl_response = list_all_subscribed_channels(access_token);
          has_errors = check_for_error(curl_response, url_api);

          // There were no errors, parse out list of channels, anchor = items
          if(!has_errors) {
            parse_response(curl_response, "items");
            
            free(curl_response);
            exit(EXIT_SUCCESS);
          }

          // #####################################################################################
          // Test if there's a 404, if so request a new token, if that is also expired then resign in using
          // Python script passing data with Interprocess Comms (Shared Memory)
          // #####################################################################################
          if(has_errors) {

            // Send CURL request new token, will need create_postfields function
            if(url_api->http_code != NULL) {
              http_code = url_api->http_code;
            }

            curl_response = setup_curl(curl_response, url_api, http_code, NULL); // Setup curl again, getting new token before previous send
            printf("%s\n", curl_response);

            // Check this newest request for tokens specificall error: invalid_grant
            has_errors = check_for_error(curl_response, url_api);
            free(curl_response);

            // There are errors and check for invalid_grant error message
            if(has_errors) {
              // See if invalid_grant, that will require relogin
              if(strcmp(url_api->http_message, "invalid_grant") == 0) {
                free(url_api->http_message);
                free(url_api);

                // Use IPC to send memory from this program to python to relogin to YouTubeData API
                cmd_data->command = "RELOGIN";
                shmkey = send_to_shared_mem(cmd_data);
                create_process_exec_py(shmkey);

              }
            }
          }
          // #####################################################################################
          // END RELOGIN SUBROUTINE
          // #####################################################################################

          // Print return
          parse_response(memory_chunk->memory, "items");

          // An error has occured
          if(url_api == NULL) {
            printf("NULL");
            exit(EXIT_FAILURE);
          }

          break;

        case 'o': // --output
          output_filename = optarg;
          break;
        
        case 'a': // --add-channel
          //shmkey = handle_mem_execpy(cmd_data, 'a', optarg);

          break;

        case 'i': // --handle-id
          handle_mem_execpy(cmd_data, 'i', optarg);

          break;

        case 'u': // --username
          handle_mem_execpy(cmd_data, 'u', optarg);

          break;

        case 'v': // --verbose
          verbose = 1;
          break;

        case '?': // User specified invalid option
          print_usage(stderr, 1);
          break;

        case -1: // Done with options
          break;


      }
  } while(next_option != -1);

  /*Done with options, OPTIND points to first nonoption arg.
    print verbose if selected */
    if(verbose)
    {
      int i;
      for(i=optind; i < argc; i++)
        printf("Argument: %s\n", argv[i]);
    }

    free(url_api->http_message);
    free(url_api);

    return 0;
}
