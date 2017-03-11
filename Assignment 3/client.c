#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include<sys/socket.h>
#include<arpa/inet.h>

#define __DEBUG
#ifdef __DEBUG 		// for debugging also displays the file, function and line in source code
// where the error was found
void debug_info(const char *file, const char *function, const int line)
{
    fprintf(stderr, "DEBUG. ERROR PLACE: File=\"%s\", Function=\"%s\", Line=\"%d\"\n", file, function, line);
}

#define ERR_MSG(DBG_MSG) { \
        perror(DBG_MSG); \
    debug_info(__FILE__, __FUNCTION__, __LINE__); \
}

#else			// with no __DEBUG just displays the error message

#define ERR_MSG(DBG_MSG) { \
    perror(DBG_MSG); \
}

#endif

//defining constants for my program

#define MAX_TH 100
#define VALID_SF_FILE 10
#define MAX_NUMBER_OF_LINES 50
#define SUCCESS 1
#define MAX_PATH_LEN 4096
#define MAX_USER_NAME_LEN 30
#define MALLOC_FAILED -1
#define OPEN_DIR_FAILED -2
#define OPEN_FILE_FAILED -3
#define READ_FILE_FAILED -4
#define INVALID_USER -5
#define GET_FILE_HEADER_FAILED -6
#define GET_SECTION_HEADER_FAILED -7
#define INVALID_ARGUMENTS -8
#define INVALID_SIGNATURE -9
#define USER_ASSIGNED_TO_SEVERAL_DIRECTORIES -10
#define GET_SECTION_DATA_BLOCK_FAILED -11
#define NOT_A_SF_FILE -12
#define WRITE_FAILED -13
#define SEMOP_FAILED -14
#define FORK_FAILED -15

#pragma pack(push)  // saves the pragma options
#pragma pack(1)     // alligns the structures to 1 byte in memory

#pragma pack(pop)   // restores the pragma options previously pushed.

int send_int(int num, int socket)
{
    int converted_number = htonl(num);

    if (send(socket, &converted_number, sizeof(converted_number), 0) < 0)
    {
        ERR_MSG("ERROR (send failed)");
    }

    return (0);
}
int receive(int *num, int socket)
{
    int received_int = 0;
    if (recv(socket, &received_int, sizeof(received_int), 0) < 0)
    {
        ERR_MSG("ERROR (recv failed)");
    }

    received_int = ntohl(received_int);
    *num = received_int;

    return (0);
}

int main(int argc, char *argv[])
{
    char *line_buffer, *aux_buffer, *user_name, *data;
    int sock_client;
    int how_much_left, bytesRead, bytes_received, aux_how_much_left;
    struct sockaddr_in server;

    line_buffer = NULL;
    aux_buffer = NULL;
    user_name = NULL;
    data = NULL;

    line_buffer = (char*)malloc(sizeof(char) * 1024);
    aux_buffer = (char*)malloc(sizeof(char) * 1024);
    user_name = (char *)malloc(sizeof(char) *1024);
    data = (char *)malloc(sizeof(char) * 5000);

    if (NULL == line_buffer)
    {
        ERR_MSG("ERROR (malloc failed)");
        exit(MALLOC_FAILED);
    }

    if (NULL == aux_buffer)
    {
        ERR_MSG("ERROR (malloc failed)");
        exit(MALLOC_FAILED);
    }

    if (NULL == user_name)
    {
        ERR_MSG("ERROR (malloc failed)");
        exit(MALLOC_FAILED);
    }

    if (NULL == data)
    {
        ERR_MSG("ERROR (malloc failed)");
        exit(MALLOC_FAILED);
    }

    scanf("%s", user_name);

    if (strlen(user_name) > MAX_USER_NAME_LEN)
    {
        ERR_MSG("Warning (user_name is too big)");
        exit(1);
    }

    //Create socket
    sock_client = socket(AF_INET , SOCK_STREAM, 0);
    if (sock_client < -1)
    {
        ERR_MSG("ERROR (could not create socket)");
        exit(1);
    }
    printf("Socket created!\n");

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(8888);

    //Connect to remote server
    if (connect(sock_client , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        ERR_MSG("ERROR (connect to server failed)");
        exit(1);
    }

    printf("Connected to server!\n");

    send_int(strlen(user_name), sock_client);

    //Send the username
    if(send(sock_client , user_name , strlen(user_name), 0) < 0)
    {
        ERR_MSG("ERROR (send failed)");
        exit(1);
    }

    receive(&how_much_left, sock_client);
    bytes_received = 0;

    while(bytes_received < how_much_left)
    {
        bytesRead = recv(sock_client, data + bytes_received, how_much_left, 0);
        bytes_received += bytesRead;
        how_much_left -= bytesRead;
    }

    printf("%s\n", data);

    if (strcmp(data, "SUCCESS: Authentication succeeded!") == 0)
    {
        //struct client_request_msg *requests;
        do {
            if (data != NULL)
            {
                free(data);
                data = NULL;
            }

            scanf("%c", &line_buffer[0]);
            scanf("%[^\n]s", line_buffer);

            send_int(strlen(line_buffer), sock_client);

            if (send(sock_client, line_buffer, strlen(line_buffer), 0) < 0) {
                ERR_MSG("ERROR (send failed)");
                exit(1);
            }

            printf("Command sent to server : %s\n", line_buffer);
            printf("Printing information from the server : \n->");

            data = (char *)malloc(sizeof(char)*5000);
            if (NULL == data)
            {
                ERR_MSG("ERROR (malloc failed)");
                exit(MALLOC_FAILED);
            }
            do
            {
                receive(&how_much_left, sock_client);

                aux_how_much_left = how_much_left;
                if (aux_how_much_left == 0)
                {
                    break;
                }
                bytes_received = 0;

                while (bytes_received < how_much_left) {
                    bytesRead = recv(sock_client, data + bytes_received, how_much_left, 0);
                    bytes_received += bytesRead;
                    how_much_left -= bytesRead;
                }

                if (strstr(data, "ERROR") != NULL) {
                    break;
                }

                data[bytes_received] = '\0';
                printf("%s\n", data);
            } while (aux_how_much_left != 0);

        } while (strcmp(line_buffer, "EXIT"));

        printf("Program ends !\n");
    }
    else
    {
        printf("ERROR: Authentication failed!\n");
        exit(1);
    }
    return (0);
}