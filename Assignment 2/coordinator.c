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
#define LSEEK_FAILED -16
#define CREATE_THREAD_FAILED -17

enum sf_sect_type
{
    SF_STYPE_RESERVED = 0,
    SF_STYPE_TEXT,
    SF_STYPE_BINARY,
    SF_STYPE_UNKNOWN,
};

#pragma pack(push)  // saves the pragma options
#pragma pack(1)     // alligns the structures to 1 byte in memory

struct sf_file_header
{
    uint32_t magic;
    uint32_t no_sections;
};

struct sf_section_header
{
    uint16_t        size;
    uint16_t        offset;
    uint16_t        type;
    uint16_t        elem_size;
    uint8_t         name_size;
    uint8_t         name[256];
};

#pragma pack(pop)   // restores the pragma options previously pushed.
struct user_and_dir
{
    char USER_DIR[MAX_PATH_LEN];
    char USER_NAME[MAX_USER_NAME_LEN]; //max length
    char valid;
};

struct section_and_key
{
    char section_name_encrypted[256];
    char *encryption_key;
};

struct th_args
{
    char file_name[256];
};

//global variables
int number_of_files;
struct sf_file_header signature;
struct sf_section_header *section_header;
int valid_SF_encrypted_file;
int section_number_encrypted;
struct user_and_dir user_and_dir_final; // user name-ul si dir-ul pentru user-ul dat la tastatura
int semaphore_id;
int for_fork = 1;
pthread_mutex_t lock;
int last_thread = 0;
uint16_t anissm_offset;
pthread_mutex_t lock_for_last_thread;
uint16_t anissm_section_header_offset;
uint16_t anissm_size;

void print_section_details(struct sf_section_header *section_header);
void scan_file(char *file_name);
void scan_dir(char *dir_name);
char* create_path(struct user_and_dir the_user_and_dir, char* file_path);
int get_section_file_header(int fd, struct sf_file_header *file_header);
int get_section_headers(int fd, struct sf_file_header *file_header, struct sf_section_header *section_header);
int get_section_data_block(int fd, struct sf_section_header *section_header, uint8_t *section_data);
void print_section_details(struct sf_section_header *section_header);
int valid_SF_file(int fd);
int check_for_equality(char *first, uint8_t *second);
int search_dir(char *dirName, char *searched_name, char *section_name, unsigned int section_size);
int search_tree(char *dirName, char *fileName, char *section_name, unsigned int section_size);
void info(char *file_path);
void search_files_and_sections(char *dir_name, char *file_name, char *section_name, unsigned int section_size, unsigned char recursive);
void sect_display(char *file_path, char *sect_name);
void sect_hash(char *file_path, char *sect_name);
void search_dir_for_scan_dir(char *dirName);
void scan_dir(char *dirName);
int get_line(int fd, char *line, int max_length);
int get_line_encrypted_file(int fd, char *line, int how_much);

void P(int semId, int semNr)
{
    struct sembuf op = {semNr, -1, 0};

    if (semop(semId, &op, 1) != 0)
    {
        ERR_MSG("ERROR (semop failed)");
        exit(SEMOP_FAILED);
    }
}

void V(int semId, int semNr)
{
    struct sembuf op = {semNr, 1, 0};
    
    if (semop(semId, &op, 1) != 0)
    {
        ERR_MSG("ERROR (semop failed)");
        exit(SEMOP_FAILED);
    }
}

/*************************************************/
/**            SECTION FILE FUNCTIONS           **/
/*************************************************/

/**
*  get_section_file_header - parses a section file header from a file and places the contents into the sf_file_header argument.
*
*  @fd: opened section file
*  @header: a pointer to an allocated structure
*
* Return:
*   0  => Function succesfully parsed a VALID section header.
*   -1 => Function failed parsing the section header or the section header was INVALID. Check errno for additional information. (use EINVAL if invalid).
**/
int get_section_file_header(int fd, struct sf_file_header *file_header)
{
    int bytesRead;
    uint32_t value;

    value = 0xB612B612;

    if ((bytesRead = read(fd, &file_header->magic, 4)) < 0)
    {
        ERR_MSG("ERROR (reading from inside the file)");
        errno = READ_FILE_FAILED;
        return errno;
    }

    if (file_header->magic != value)
    {
        errno = EINVAL;
        return errno;
    }

    if (file_header->magic <= 0)
    {
        ERR_MSG("ERROR (invalid signature)");
        errno = INVALID_SIGNATURE;
        return errno;
    }

    if ((bytesRead = read(fd, &file_header->no_sections, 4)) < 0)
    {
        ERR_MSG("ERROR (reading from inside the file)");
        errno = READ_FILE_FAILED;
        return errno;
    }

    if (file_header->no_sections <= 0)
    {
        ERR_MSG("ERROR (invalid number of sections)");
        errno = EINVAL;
        return errno;
    }

    errno = SUCCESS;
    return errno;
}

/**
* get_section_headers - parses sf_file_header.no_sections from the section file and places the contents into the sf_section_header array argument.
*
* @fd: opened section file
* @file_header: a parsed section file header, use get_section_file_header()
* @section_header: an array of at least sf_file_header.no_sections allocated structures
*
* WARNING: Use get_section_file_header to obtain the sf_file_header.
*
* Return:
*   0  => Function succesfully parsed a VALID section header.
*   -1 => Function failed parsing the section header or the section header was INVALID. Check errno for additional information. (use EINVAL if invalid).
**/
int get_section_headers(int fd, struct sf_file_header *file_header, struct sf_section_header *section_header)
{
    int bytesRead, i;

    i = 0;
    errno = SUCCESS;

    while (i < file_header->no_sections)
    {
        if ((bytesRead = read(fd, &section_header[i].size, 2)) < 0)
        {
            ERR_MSG("ERROR (reading from inside the file)");
            errno = READ_FILE_FAILED;
            return errno;
        }

        if (section_header[i].size <= 0)
        {
            //ERR_MSG("ERROR (invalid size of a section)");
            errno = EINVAL;
            return errno;
        }

        if ((bytesRead = read(fd, &section_header[i].offset, 2)) < 0)
        {
            ERR_MSG("ERROR (reading from inside the file)");
            errno = READ_FILE_FAILED;
            return errno;
        }

        if (section_header[i].offset <= 0)
        {
            //ERR_MSG("ERROR (invalid offset of a section)");
            errno = EINVAL;
            return errno;
        }

        if ((bytesRead = read(fd, &section_header[i].type, 2)) < 0)
        {
            ERR_MSG("ERROR (reading from inside the file)");
            errno = READ_FILE_FAILED;
            return errno;
        }

        if ((bytesRead = read(fd, &section_header[i].elem_size, 2)) < 0)
        {
            ERR_MSG("ERROR (reading from inside the file)");
            errno = READ_FILE_FAILED;
            return errno;
        }

        if (section_header[i].elem_size <= 0)
        {
            //ERR_MSG("ERROR (invalid elem_size of a section)");
            errno = EINVAL;
            return errno;
        }

        if ((bytesRead = read(fd, &section_header[i].name_size, 1)) < 0)
        {
            ERR_MSG("ERROR (reading from inside the file)");
            errno = READ_FILE_FAILED;
            return errno;
        }

        if (section_header[i].name_size <= 0)
        {
            //ERR_MSG("ERROR (invalid elem_size of a section)");
            errno = EINVAL;
            return errno;
        }

        if ((bytesRead = read(fd, section_header[i].name, section_header[i].name_size)) < 0)
        {
            ERR_MSG("ERROR (reading from inside the file)");
            errno = READ_FILE_FAILED;
            return errno;
        }
        section_header[i].name[section_header[i].name_size] = '\0';

        if (check_for_equality("SECT_ANISSM", (uint8_t *)section_header[i].name))
        {
            anissm_section_header_offset = lseek(fd, 0, SEEK_CUR) - 20;
            //printf("%02X\n", anissm_section_header_offset);
        }
        i++;
    }

    return errno;
}

/**
* get_section_data_block - parses a section data block described by SF_SECTION_HEADER argument and places the contents into the SectionData argument.
*
* @fd: opened section file
* @section_header: a parsed section header, use get_section_headers()
* @section_data: an array of at least sf_section_header.size allocated bytes
*
* WARNING: Use get_section_headers to obtain the sf_section_header.
*
* Return:
*   0  => Function succesfully parsed a VALID section header.
*   -1 => Function failed parsing the section header or the section header was INVALID. Check errno for additional information. (use EINVAL if invalid).
**/
int get_section_data_block(int fd, struct sf_section_header *section_header, uint8_t *section_data)
{
    int bytesRead;

    lseek(fd, section_header->offset, SEEK_SET);

    if ((bytesRead = read(fd, section_data, section_header->size)) < 0)
    {
        ERR_MSG("ERROR (reading from inside the file)");
        errno = READ_FILE_FAILED;
        return errno;
    }

    errno = SUCCESS;
    return errno;
}

/**
* print_section_details - prints the contets of a sf_section_header structure.
*
* @section_header: a parsed section header, use get_section_headers()
**/
void print_section_details(struct sf_section_header *section_header)
{
    int i;

    i = 0;

    while (i < signature.no_sections)
    {
        printf("Section %d: ", (i + 1));

        printf("\t Size: %X\n", section_header[i].size);

        printf("\t\t Offset: %X\n", section_header[i].offset);

        switch (section_header[i].type)
        {
        case 0:
            printf("\t\t Type: RESERVED\n");
            break;
        case 1:
            printf("\t\t Type: TEXT\n");
            break;
        case 2:
            printf("\t\t Type: BINARY\n");
            break;
        case 4:
            printf("\t\t Type: UNKNOWN\n");
            break;
        }

        printf("\t\t Elem size: %X\n", section_header[i].elem_size);

        printf("\t\t Number of elements: %d\n", section_header[i].size / section_header[i].elem_size);

        printf("\t\t Name's size: %X\n", section_header[i].name_size);

        printf("\t\t Name: %s\n", section_header[i].name);

        i++;
    }
}

/*************************************************/
/**          SF VALIDATE FUNCTIONS              **/
/*************************************************/
int valid_SF_file(int fd)
{
    int bytesRead;
    uint32_t magic;
    uint32_t value;

    value = 0xB612B612;
    magic = 0;
    section_header = NULL;

    // Try reading from inside the file
    //printf("OPERATION: Reading the signature and number of sections from the file!\n");
    if (SUCCESS != get_section_file_header(fd, &signature))
    {
        return(NOT_A_SF_FILE);
    }
    else
    {
        if (signature.no_sections <= 0 || signature.no_sections > 100) {
            return (NOT_A_SF_FILE);
        }

        section_header = (struct sf_section_header *) malloc(
                (sizeof(struct sf_section_header)) * signature.no_sections);

        if (NULL == section_header) {
            ERR_MSG("ERROR: (malloc failed)");
            exit(MALLOC_FAILED);
        }

        // Try reading from inside the file
        //printf("OPERATION: Reading the sections's characteristics from the file!\n");
        if (SUCCESS != get_section_headers(fd, &signature, section_header)) {
            //ERR_MSG("ERROR (get_section_headers failed)");
            return (NOT_A_SF_FILE);
        }
        else {
            //print_section_details(section_header);
        }

        if ((bytesRead = read(fd, &magic, 4)) < 0) {
            ERR_MSG("ERROR (reading from inside the file)");
        }

        if (magic != value) {
            return (NOT_A_SF_FILE);
        }
        else {
            return (VALID_SF_FILE);
        }
    }
}

/*************************************************/
/**             HELPER FUNCTIONS                **/
/*************************************************/
int check_for_equality(char *first, uint8_t *second)
{
    int i;

    i = 0;
   
    if (first[i] == (char)second[i] && (strlen(first) == strlen((char *)second)))
    {
        while ((first[i] == (char)second[i]) && (i < strlen(first)))
        {
            i++;
        }
    }

    if (i == strlen(first))
    {
        return(1);
    }
    return(0);
}

int get_line(int fd, char *line, int max_length)
{
    int position, value;
    char c;

    position = 0;
    line[position] = '\0';
    while (((value = read(fd, &c, 1)) != 0) && (position < max_length))
    {
        if (c == '\n')
        {
            line[position] = '\0';
            break;
        }
        line[position] = c;
        position++;
    }
    if (value == 0)
    {
        return (0);
    }
    return (1);
}

int get_line_encrypted_file(int fd, char *line, int how_much)
{
    int position, value;
    char c;

    position = 0;
    line[position] = '\0';
    
    while (((value = read(fd, &c, 1)) != 0) && (how_much + value <= section_header[section_number_encrypted].size + section_header[section_number_encrypted].offset))
    {
        how_much = how_much + value;
        if (c == '\n')
        {
            line[position] = '\0';
            break;
        }
        line[position] = c;
        position++;
    }
    if (value == 0)
    {
        return (0);
    }
    return (1);
}

char *create_path(struct user_and_dir the_user_and_dir, char *file_path)
{
    char *file_name_user;

    file_name_user = NULL;

    file_name_user = (char *)malloc(sizeof(char) * (MAX_PATH_LEN + 1));
    if (NULL == file_name_user)
    {
        ERR_MSG("ERROR (malloc failed)");
        exit(MALLOC_FAILED);
    }

    if (file_path != NULL)
    {
        snprintf(file_name_user, MAX_PATH_LEN, "%s/%s", the_user_and_dir.USER_DIR, file_path);
        //printf("%s\n", file_path);
        //printf("%s\n", the_user_and_dir.USER_DIR);
        file_name_user[strlen(file_name_user)] = '\0';
        //printf("FILE path : %s\n", file_name_user);
        return (file_name_user);
    }
    else
    {
        strncpy(file_name_user, the_user_and_dir.USER_DIR, strlen(the_user_and_dir.USER_DIR) + 1);
        return (file_name_user);
    }
}

/**
function search_dir = searches a directory contents
**/
int search_dir(char *dirName, char *searched_name, char *section_name, unsigned int section_size)
{
    DIR* dir;
    struct dirent *dirEntry;
    struct stat inode;
    char name[MAX_PATH_LEN];
    int i, ok;

    dir = opendir(dirName);
    if (dir == 0) {
        ERR_MSG("Error opening directory");
        exit(OPEN_DIR_FAILED);
    }

    // iterate the directory contents
    while ((dirEntry = readdir(dir)) != 0)
    {
        // build the complete path to the element in the directory
        snprintf(name, MAX_PATH_LEN, "%s/%s", dirName, dirEntry->d_name);

        // get info about the directory's element
        lstat(name, &inode);

        if (S_ISREG(inode.st_mode))
            if (strstr(dirEntry->d_name, searched_name) != NULL)
            {
                printf("File found: %s \n", name);
                if (section_name != NULL)
                {
                    int fd;

                    if ((fd = open(name, O_RDONLY)) < 0)
                    {
                        ERR_MSG("ERROR (opening the file)");
                        exit(OPEN_FILE_FAILED);
                    }

                    if (valid_SF_file(fd) == VALID_SF_FILE)
                    {
                        i = 0;
                        ok = 0;
                        while ((i < signature.no_sections) && (ok == 0))
                        {
                            if (check_for_equality(section_name, section_header[i].name) != 0)
                            {
                                if (section_size != 0)
                                {
                                    if (section_header[i].size >= section_size)
                                    {
                                        printf("%s ", searched_name);
                                        printf("%s ", section_header[i].name);
                                        printf("%d ", section_header[i].size);
                                        ok = 1;
                                    }
                                }
                                else if (section_size == 0)
                                {
                                    printf("%s ", searched_name);
                                    printf("%s ", section_header[i].name);
                                    ok = 1;
                                }
                            }
                            i++;
                        }
                    }
                }
            }
    }
    closedir(dir);
    return (0);
}
/**
function search_tree = searches a directory recursively
**/
int search_tree(char *dirName, char *fileName, char *section_name, unsigned int section_size)
{
    DIR* dir;
    struct dirent *dirEntry;
    struct stat inode;
    char name[MAX_PATH_LEN];

    dir = opendir(dirName);
    if (dir == 0) {
        ERR_MSG("Error opening directory");
        exit(OPEN_DIR_FAILED);
    }

    search_dir(dirName, fileName, section_name, section_size);
    // iterate the directory contents
    while ((dirEntry = readdir(dir)) != 0) {
        // build the complete path to the element in the directory
        snprintf(name, MAX_PATH_LEN, "%s/%s", dirName, dirEntry->d_name);

        // get info about the directory's element
        lstat(name, &inode);

        // test the type of the directory's element
        if (S_ISDIR(inode.st_mode))
        {
            if ((strcmp(dirEntry->d_name, ".") != 0) && (strcmp(dirEntry->d_name, "..") != 0))
            {
                search_tree(name, fileName, section_name, section_size);
            }
        }
    }
    closedir(dir);
    return(0);
}

/*************************************************/
/**             COMMANDS FUNCTIONS              **/
/*************************************************/
void info(char *file_path)
{
    int fd, i;
    uint8_t *section_data;

    section_data = NULL;

    if ((fd = open(file_path, O_RDONLY)) < 0)
    {
        ERR_MSG("ERROR (opening the file)");
        exit(OPEN_FILE_FAILED);
    }
    printf("SF's file's path: %s\n", file_path);
    
    if (NOT_A_SF_FILE == valid_SF_file(fd))
    {
        ERR_MSG("ERROR: not a SF file");
    }
    else
    {
        printf("Valid SF file!\n");
    }

    i = 0;
    while (i < signature.no_sections)
    {
        section_data = (uint8_t *)malloc(sizeof(uint8_t) * (section_header[i].size + 1));

        if (NULL == section_data)
        {
            ERR_MSG("ERROR: (malloc failed)");
            exit(MALLOC_FAILED);
        }

        printf("Section %d data block: \n", (i + 1));
        if (get_section_data_block(fd, &section_header[i], section_data) != SUCCESS)
        {
            ERR_MSG("ERROR: (get_section_data_block failed)");
            exit(GET_SECTION_DATA_BLOCK_FAILED);
        }

        if (NULL != section_data)
        {
            free(section_data);
            section_data = NULL;
        }
        i++;
    }
}

void search_files_and_sections(char *dir_name, char *file_name, char *section_name, unsigned int section_size, unsigned char recursive)
{
    if (recursive == 1)
    {
        printf("%s %s %s %d\n", dir_name, file_name, section_name, section_size);
        search_tree(dir_name, file_name, section_name, section_size);
    }
    else
    {
        printf("%s %s %s %d\n", dir_name, file_name, section_name, section_size);
        search_dir(dir_name, file_name, section_name, section_size);

    }
}

void sect_display(char *file_path, char *sect_name)
{
    int fd, i;
    uint8_t *section_data;

    section_data = NULL;

    if ((fd = open(file_path, O_RDONLY)) < 0)
    {
        ERR_MSG("ERROR (opening the file)");
        exit(OPEN_FILE_FAILED);
    }
    printf("SF's file's path: %s\n", file_path);

    if (NOT_A_SF_FILE == valid_SF_file(fd))
    {
        ERR_MSG("ERROR: not a SF file");
    }

    for (i = 0; i < signature.no_sections; i++)
    {
        if (check_for_equality(sect_name, section_header[i].name) != 0)
        {
            if (section_header[i].type == 1)
            {
                section_data = (uint8_t *)malloc(sizeof(uint8_t) * (section_header[i].size + 1));

                if (NULL == section_data)
                {
                    ERR_MSG("ERROR: (malloc failed)");
                    exit(MALLOC_FAILED);
                }

                if (get_section_data_block(fd, &section_header[i], section_data) != SUCCESS)
                {
                    ERR_MSG("ERROR: (get_section_data_block failed)");
                    exit(GET_SECTION_DATA_BLOCK_FAILED);
                }

                if (NULL != section_data)
                {
                    free(section_data);
                    section_data = NULL;
                }
            }
            else
            {
                ERR_MSG("ERROR: not a SF file or not a TEXT section");
            }
        }
    }

}

void sect_hash(char *file_path, char *sect_name)
{
    int fd, i;
    uint8_t *section_data;

    section_data = NULL;

    if ((fd = open(file_path, O_RDONLY)) < 0)
    {
        ERR_MSG("ERROR (opening the file)");
        exit(OPEN_FILE_FAILED);
    }
    printf("SF's file's path: %s\n", file_path);

    if (NOT_A_SF_FILE == valid_SF_file(fd))
    {
        ERR_MSG("ERROR: not a SF file");
    }

    for (i = 0; i < signature.no_sections; i++)
    {
        if ((check_for_equality(sect_name, section_header[i].name) != 0) && (section_header[i].type == 2))
        {
            section_data = (uint8_t *)malloc(sizeof(uint8_t) * (section_header[i].size + 1));

            if (NULL == section_data)
            {
                ERR_MSG("ERROR: (malloc failed)");
                exit(MALLOC_FAILED);
            }

            if (get_section_data_block(fd, &section_header[i], section_data) != SUCCESS)
            {
                ERR_MSG("ERROR: (get_section_data_block failed)");
                exit(GET_SECTION_DATA_BLOCK_FAILED);
            }

            if (NULL != section_data)
            {
                free(section_data);
                section_data = NULL;
            }
        }
        else
        {
            ERR_MSG("ERROR: not a SF file or not a BINARY section");
        }
    }
}

void scan_file(char *file_name)
{
    int i, fd;

    valid_SF_encrypted_file = 0;

    if ((fd = open(file_name, O_RDONLY)) < 0)
    {
        ERR_MSG("ERROR (opening the file)");
        exit(OPEN_FILE_FAILED);
    }
    //printf("SF's file's path: %s\n", file_name);

    if (NOT_A_SF_FILE == valid_SF_file(fd))
    {
        //printf("ERROR: not a SF file\n");
    }
    else
    {
        i = 0;
        while (i < signature.no_sections)
        {
            if ((check_for_equality("SECT_ANISSM", (uint8_t *)section_header[i].name)) && (section_header[i].type == 0))
            {
                valid_SF_encrypted_file = 1;
                section_number_encrypted = i;
                i = signature.no_sections;
            }
            i++;
        }
        P(semaphore_id, 0);
        if (valid_SF_encrypted_file == 1)
        {
            printf("%s : INFECTED WITH ANISSM\n", file_name);
        }
        else
        {
            printf("%s: NOT INFECTED WITH ANISSM\n", file_name);
        }
        V(semaphore_id, 0);
    }
}

void search_dir_for_scan_dir(char *dirName)
{
    DIR* dir;
    struct dirent *dirEntry;
    struct stat inode;
    char name[MAX_PATH_LEN];

    dir = opendir(dirName);
    if (dir == 0)
    {
        ERR_MSG("Error opening directory");
        exit(OPEN_DIR_FAILED);
    }
   
    // iterate the directory contents
    while (((dirEntry = readdir(dir)) != 0))
    {
        if (for_fork != 0)
        {
            // build the complete path to the element in the directory
            snprintf(name, MAX_PATH_LEN, "%s/%s", dirName, dirEntry->d_name);

            // get info about the directory's element
            lstat(name, &inode);

            //else
            if (S_ISREG(inode.st_mode)) {
                P(semaphore_id, 0);
                if ((for_fork = fork()) == 0) {
                    scan_file(name);
                    exit(1);
                }
                else if (for_fork == -1) {
                    ERR_MSG("ERROR (fork failed)");
                    exit(FORK_FAILED);
                }
                V(semaphore_id, 0);
            }
        }
        if (for_fork == 0)
        {
            break;
        }
    }
    closedir(dir);
}

void scan_dir(char *dirName)
{
    DIR* dir;
    struct dirent *dirEntry;
    struct stat inode;
    char name[MAX_PATH_LEN];
    int pid;

    dir = opendir(dirName);
    if (dir == 0)
    {
        ERR_MSG("Error opening directory");
        exit(OPEN_DIR_FAILED);
    }
    
    search_dir_for_scan_dir(dirName);
    // iterate the directory contents
    while ((dirEntry = readdir(dir)) != 0) {
        if (for_fork != 0)
        {
            // build the complete path to the element in the directory
            snprintf(name, MAX_PATH_LEN, "%s/%s", dirName, dirEntry->d_name);

            // get info about the directory's element
            lstat(name, &inode);

            // test the type of the directory's element
            if (S_ISDIR(inode.st_mode))
            {
                if ((strcmp(dirEntry->d_name, ".") != 0) && (strcmp(dirEntry->d_name, "..") != 0))
                {
                    scan_dir(name);
                }
            }
        }
        if (for_fork == 0)
        {
            break;
        }
    }

    //wait for the processes
    while ((pid = waitpid(-1, NULL, 0)))
    {
        if (errno == ECHILD)
        {
            break;
        }
    }
    closedir(dir);
    for_fork = 1;
}

/**
* cleaning_section_header - parses the file and places the new content into the sf_section_header of the file.
*                           Also cleans the SECT_ANISSM section_data_block.
*
* file_name - the file to be opened
**/
void cleaning_section_header(char *file_name)
{
    int fd, bytesRead, i, final_value, position, ok, m, initial_position, zero;
    struct sf_file_header aux;
    struct sf_section_header *section_header_aux;

    section_header_aux = NULL;

    if ((fd = open(file_name, O_RDWR)) < 0)
    {
        ERR_MSG("ERROR (opening the file)");
        exit(OPEN_FILE_FAILED);
    }

    lseek(fd, 0, SEEK_SET);

    if ((bytesRead = read(fd, &aux.magic, 4)) < 0)
    {
        ERR_MSG("ERROR (reading from inside the file)");
        exit(READ_FILE_FAILED);
    }

    if ((bytesRead = read(fd, &aux.no_sections, 4)) < 0)
    {
        ERR_MSG("ERROR (reading from inside the file)");
        exit(READ_FILE_FAILED);
    }

    if (lseek(fd, 4, SEEK_SET) < 0)
    {
        ERR_MSG("ERROR (lseek failed)");
        exit(LSEEK_FAILED);
    }

    aux.no_sections--;
    if (write(fd, &aux.no_sections, sizeof(aux.no_sections)) < 0)
    {
        ERR_MSG("ERROR (write failed)");
        exit(WRITE_FAILED);
    }
    aux.no_sections++;

    section_header_aux = (struct sf_section_header *)malloc((sizeof(struct sf_section_header) - 256) * aux.no_sections);
    if (NULL == section_header_aux)
    {
        ERR_MSG("ERROR (malloc failed)");
        exit(MALLOC_FAILED);
    }

    i = 0;
    while (i < aux.no_sections)
    {
        if ((bytesRead = read(fd, &section_header_aux[i].size, 2)) < 0)
        {
            ERR_MSG("ERROR (reading from inside the file)");
            exit(READ_FILE_FAILED);
        }

        if ((bytesRead = read(fd, &section_header_aux[i].offset, 2)) < 0)
        {
            ERR_MSG("ERROR (reading from inside the file)");
            exit(READ_FILE_FAILED);
        }

        if ((bytesRead = read(fd, &section_header_aux[i].type, 2)) < 0)
        {
            ERR_MSG("ERROR (reading from inside the file)");
            exit(READ_FILE_FAILED);
        }

        if ((bytesRead = read(fd, &section_header_aux[i].elem_size, 2)) < 0)
        {
            ERR_MSG("ERROR (reading from inside the file)");
            exit(READ_FILE_FAILED);
        }

        if ((bytesRead = read(fd, &section_header_aux[i].name_size, 1)) < 0)
        {
            ERR_MSG("ERROR (reading from inside the file)");
            exit(READ_FILE_FAILED);
        }

        if ((bytesRead = read(fd, section_header_aux[i].name, section_header_aux[i].name_size)) < 0)
        {
            ERR_MSG("ERROR (reading from inside the file)");
            exit(READ_FILE_FAILED);
        }

        if (check_for_equality("SECT_ANISSM", (uint8_t *)section_header_aux[i].name) != 0)
        {
            ok = 1;
            //position - where the ANISSM ends
            position = lseek(fd, 0, SEEK_CUR);
            if (position < 0)
            {
                ERR_MSG("ERROR (lseek failed)");
                exit(LSEEK_FAILED);
            }
        }
        //final value = offset of where the sections ends
        final_value = lseek(fd, 0, SEEK_CUR);
        if (final_value < 0)
        {
            ERR_MSG("ERROR (lseek failed)");
            exit(LSEEK_FAILED);
        }
        i++;
    }

    //offset_signature - where the signature is now
    int offset_signature = lseek(fd, 0, SEEK_CUR);
    if (ok == 1)
    {
        //initial position = where the ANISSM section starts
        char read_char;
        if ((initial_position = lseek(fd, (position - 20), SEEK_SET)) < 0)
        {
            ERR_MSG("ERROR (lseek failed)");
            exit(LSEEK_FAILED);
        }

        //printf("INITIAL position : %02X\n", initial_position);
        //printf("POSITION : %02X\n", position);

        m = 0;
        for (i = position; i < offset_signature + 4; i++)
        {

            lseek(fd, (position + m), SEEK_SET);
            if ((bytesRead = read(fd, &read_char, 1)) < 0)
            {
                ERR_MSG("ERROR (reading from inside the file)");
                exit(READ_FILE_FAILED);
            }
            lseek(fd, (initial_position + m), SEEK_SET);
            if (write(fd, &read_char, 1) < 0)
            {
                ERR_MSG("ERROR (write failed)");
                exit(WRITE_FAILED);
            }
            m++;
        }

        //here I'm writing zero's
        zero = 0;
        //printf("%d\n", signature.no_sections);
        for (i = offset_signature; i < offset_signature + 20; i++)
        {
            if (write(fd, &zero, 1) < 0)
            {
                ERR_MSG("ERROR (write failed)");
                exit(WRITE_FAILED);
            }
        }
    }

    printf("CLEANING SUCCEDED!\n");

    if (section_header_aux != NULL)
    {
        free(section_header_aux);
        section_header_aux = NULL;
    }
}

/**
* cleaning_section - this function looks for which section has the name given in the argument, opens the file
*                    and goes to the section's offset given ans decrypts it.
*
* @args: the structure containing the file_name and another structure section_and_key from where we take the section's name
* and the key to decrpyt the sections' data block
*
* Return: NULL
**/
void* cleaning_section(void * args)
{
    struct th_args thread_arg = *((struct th_args*) args);
    struct section_and_key sectionKey;
    int how_much, i, section_number, value, j, fd, zero;
    char *buffer, *aux_buffer, *line_buffer, *pch;
    
    buffer = NULL;
    i = 0;
    section_number = 0;
    line_buffer = NULL;
    aux_buffer = NULL;

    if ((fd = open(thread_arg.file_name, O_RDWR)) < 0)
    {
        ERR_MSG("ERROR (opening the file)");
        exit(OPEN_FILE_FAILED);
    }

    line_buffer = (char *)malloc(sizeof(char) * 4096);
    if (NULL == line_buffer)
    {
        ERR_MSG("ERROR (malloc failed)");
        exit(MALLOC_FAILED);
    }

    aux_buffer = (char *)malloc(sizeof(char) * 4096);
    if (NULL == aux_buffer)
    {
        ERR_MSG("ERROR (malloc failed)");
        exit(MALLOC_FAILED);
    }

    ///// LOCK
    if (pthread_mutex_lock(&lock) != 0)
    {
        ERR_MSG("ERROR (Cannot take the lock)");
        exit(-20);
    }

    // this anissm_offset is upgraded after each reading
    if (lseek(fd, anissm_offset, SEEK_CUR) < 0)
    {
        ERR_MSG("ERROR (lseek failed)");
        exit(LSEEK_FAILED);
    }

    // I take the line corresponding to each thread
    value = get_line_encrypted_file(fd, line_buffer, anissm_offset);

    // if the line is not in the format need or we finished the section's data block we stop
    if ((value != 0) && (strstr(line_buffer, "SECT") != NULL))
    {
        strncpy(aux_buffer, line_buffer, strlen(line_buffer) + 1);

        pch = strtok(line_buffer, " ");
        if (pch != NULL)
        {
            if (strlen(pch) < 256 && strlen(pch) > 0)
            {
                strncpy(sectionKey.section_name_encrypted, pch, strlen(pch) + 1);
                //printf("%s\n", sectionKey.section_name_encrypted);

            }

            pch = strtok(NULL, " ");
            if (pch != NULL)
            {
                sectionKey.encryption_key = NULL;
                sectionKey.encryption_key = (char *) malloc(sizeof(char) * (strlen(pch) + 1));
                if (NULL == sectionKey.encryption_key)
                {
                    ERR_MSG("ERROR (malloc failed)");
                    exit(MALLOC_FAILED);
                }

                strncpy(sectionKey.encryption_key, pch, strlen(pch) + 1);
            }
        }
    }
    //I've taken in the if above the section's name and the encryption key

    //printf("%s %s\n", sectionKey.section_name_encrypted, sectionKey.encryption_key);

    //I'm going to the section's offset for padding with 0's it's line
    zero = 0;
    if (lseek(fd, anissm_offset, SEEK_SET) < 0)
    {
        ERR_MSG("ERROR (lseek failed)");
        exit(LSEEK_FAILED);
    }
    for (i = 0; i< (strlen(aux_buffer) + 1); i++)
    {
        if (write(fd, &zero, 1) < 0)
        {
            ERR_MSG("ERROR (write failed)");
            exit(WRITE_FAILED);
        }
    }

    buffer = (char *)malloc(sizeof(char) * strlen(sectionKey.encryption_key));
    if (NULL == buffer)
    {
        ERR_MSG("ERROR (malloc failed)");
        exit(MALLOC_FAILED);
    }

    //update offset
    anissm_offset = lseek(fd, 0, SEEK_CUR);

    //printf("OFFSET anissm : %02X\n", anissm_offset);

    // look for what section's has the name read from the section ANISSM's data block
    // and take it's number
    i = 0;
    //printf("%d signature \n", signature.no_sections);
    while(i < signature.no_sections)
    {
        //printf("Name : %s\n", section_header[i].name);
        if (check_for_equality(sectionKey.section_name_encrypted, (uint8_t *)section_header[i].name) != 0)
        {
            section_number = i;
            i = signature.no_sections;
        }
        i++;
    }

    // this commented code is used for checking the length of the encryption key with the elem_size
    if (strlen(sectionKey.encryption_key) % section_header[section_number].elem_size != 0)
    {
        printf("Different elem size from the length of the encryption key!\n");
        printf("This section won't be cleaned : %s!\n", section_header[section_number].name);
        return (NULL);
    }
    //printf("Offset : %02X\n", section_header[section_number].offset);
    how_much = section_header[section_number].offset;

    //writing back in the section header the size of the SECT_ANISSM data block after removing it's line
    anissm_size = anissm_size - strlen(aux_buffer);

    lseek(fd, anissm_section_header_offset, SEEK_SET);

    if (write(fd, &anissm_size, 2) < 0)
    {
        ERR_MSG("ERROR (write failed)");
        exit(WRITE_FAILED);
    }

    /// UNLOCK
    if (pthread_mutex_unlock(&lock) != 0)
    {
        ERR_MSG("Cannot release the lock");
        exit(5);
    }


    int val = lseek(fd, section_header[section_number].offset, SEEK_SET);

    /////////////////////////////// converting the key !

    int p;
    uint8_t array_bytes[section_header[section_number].elem_size];
    for (p = 0; p < section_header[section_number].elem_size; p++)
    {
        sscanf(&sectionKey.encryption_key[p*2],"%02x", (unsigned int *)&array_bytes[p]);
    }

    /*for (p = 0; p < section_header[section_number].elem_size; p++)
    {
        printf("%02X\n", array_bytes[p]);
    }*/

    //how_much is the offset of the ANISSM's section
    how_much = val;

    //decrypting the section with the key given and writing it back
    while (((value = read(fd, buffer, section_header[section_number].elem_size)) != 0) && (how_much + value <= section_header[section_number].size + section_header[section_number].offset))
    {
        how_much = how_much + value;
        for (j = 0; j < strlen(buffer); j++)
        {
            buffer[j] = buffer[j] ^ array_bytes[j];
        }

        val = lseek(fd, (how_much - value), SEEK_SET);
 
        if ((val = write(fd, buffer, strlen(buffer))) < 0)
        {
            ERR_MSG("ERROR (write failed)");
            exit(val);
        }
    }
    
    printf("Decrypting succeeded\n");

    /// LOCK
    if (pthread_mutex_lock(&lock_for_last_thread) != 0)
    {
        ERR_MSG("Cannot release the lock");
        exit(5);
    }
    if (last_thread == 1)
    {
        cleaning_section_header(thread_arg.file_name);
        last_thread = 0;
    }
    else
    {
        last_thread--;
    }
    /// UNLOCK
    if (pthread_mutex_unlock(&lock_for_last_thread) != 0)
    {
        ERR_MSG("Cannot release the lock");
        exit(5);
    }
    
    if (buffer != NULL)
    {
        free(buffer);
        buffer = NULL;
    }
    if (line_buffer != NULL)
    {
        free(line_buffer);
        line_buffer = NULL;
    }
    if (aux_buffer != NULL)
    {
        free(aux_buffer);
        aux_buffer = NULL;
    }

    return (NULL);
}

void clean_file(char *file_name)
{
    uint8_t *section_data;
    int fd, i, j, value;
    pthread_t *th;
    char *line_buffer;

    section_data = NULL;
    th = NULL;

    // checking if the file is SF
    scan_file(file_name);
    if (valid_SF_encrypted_file == 1)
    {
        if ((fd = open(file_name, O_RDWR)) < 0)
        {
            ERR_MSG("ERROR (opening the file)");
            exit(OPEN_FILE_FAILED);
        }

        section_data = (uint8_t *)malloc(sizeof(uint8_t) * (section_header[section_number_encrypted].size + 1));
        if (NULL == section_data)
        {
            ERR_MSG("ERROR: (malloc failed)");
            exit(MALLOC_FAILED);
        }

        line_buffer = (char *)malloc(sizeof(char) * 4096);
        if (NULL == line_buffer)
        {
            ERR_MSG("ERROR (malloc failed)");
            exit(MALLOC_FAILED);
        }

        if (get_section_data_block(fd, &section_header[section_number_encrypted], section_data) != SUCCESS)
        {
            ERR_MSG("ERROR: (get_section_data_block failed)");
        }

        //printf("%s\n", section_data);
        
        if (lseek(fd, section_header[section_number_encrypted].offset, SEEK_SET) < 0)
        {
            ERR_MSG("ERROR (lseek failed)");
            exit(LSEEK_FAILED);
        }

        i = 0;
        //reading the lines of the ANISSM's section data block to know how many sections are encrypted
        while ((value = get_line_encrypted_file(fd, line_buffer, section_header[section_number_encrypted].offset)) != 0)
        {
            if (strstr(line_buffer, "SECT") == NULL)
            {
                break;
            }
            i++;
        }

        // Create the lock to provide mutual exclusion for the concurrent threads
        if (pthread_mutex_init(&lock, NULL) != 0)
        {
            ERR_MSG("Cannot initialize the lock");
            exit(2);
        }

        if (pthread_mutex_init(&lock_for_last_thread, NULL) != 0)
        {
            ERR_MSG("Cannot initialize the lock");
            exit(2);
        }


        // threads -> create threadd
        th = (pthread_t *)malloc(sizeof(pthread_t) * signature.no_sections);

        if (NULL == th)
        {
            ERR_MSG("ERROR (malloc failed)");
            exit(MALLOC_FAILED);
        }


        anissm_offset = section_header[section_number_encrypted].offset;

        //taking the size of the ANISSM section header
        anissm_size = section_header[section_number_encrypted].size;
        struct th_args thread_args[i];
        last_thread = i;

        //creating the threads for the sections
        for (j = 0; j < i; j++)
        {
            strncpy(thread_args[j].file_name, file_name, strlen(file_name) + 1);

            thread_args[j].file_name[strlen(file_name)] = '\0';
            if (pthread_create(&th[j], NULL, &cleaning_section, (void *)&thread_args[j]) != 0 )
            {
                ERR_MSG("ERROR (cannot create thread)");
                exit(CREATE_THREAD_FAILED);
            }
        }

        //wait for threads
        for (j = 0; j < i; j++)
        {
            pthread_join(th[j], NULL);
        }

        //cleaning part
        if (th != NULL)
        {
            free(th);
            th = NULL;
        }

        // Remove the lock
        if (pthread_mutex_destroy(&lock) != 0)
        {
            ERR_MSG("Cannot destroy the lock");
            exit(-20);
        }

        //freeing memory area
        if (section_data != NULL)
        {
            free(section_data);
            section_data = NULL;
        }

        if (line_buffer != NULL)
        {
            free(line_buffer);
            line_buffer = NULL;
        }
    }
}

void validate_config_file(char *file, struct user_and_dir *from_config)
{
    int fd, value, number, ok, users_and_dirs;
    char *line_buffer, *aux_buffer;
    char *pch;

    line_buffer = NULL;
    aux_buffer = NULL;
    users_and_dirs = 0;

    line_buffer = (char*)malloc(sizeof(char) * 1024);
    aux_buffer = (char*)malloc(sizeof(char) * 1024);

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

    if ((fd = open(file, O_RDONLY)) < 0)
    {
        ERR_MSG("ERROR (opening the file)");
        exit(OPEN_FILE_FAILED);
    }

    while ((value = get_line(fd, line_buffer, 1024)) != 0)
    {
        strncpy(aux_buffer, line_buffer, 1024);

        number = 0;
        pch = strtok(line_buffer, " ");
        while (pch != NULL)
        {
            // in case it splits and the last remained is a new line
            if (pch[0] != '\n')
            {
                number++;
            }
            if (number == 1)
            {
                if (opendir(pch) != 0)
                {
                    strncpy(from_config[users_and_dirs].USER_DIR, pch, strlen(pch) + 1);
                    ok = 1;
                }
                else
                {
                    ok = 0;
                }
            }
            if ((number == 2) && (ok == 1) && (pch[0] != '\n'))
            {

                strncpy(from_config[users_and_dirs].USER_NAME, pch, strlen(pch) + 1);
            }

            pch = strtok(NULL, " ");
        }
        // if it's only 2 then we have the valid line format
        if ((number < 3 && number > 1) && (ok == 1))
        {
            printf("VALID: %s\n", aux_buffer);
            from_config[users_and_dirs].valid = '1';
            users_and_dirs++;
        }
        else
        {
            printf("INVALID: %s\n", aux_buffer);
            from_config[users_and_dirs].valid = '0';
            users_and_dirs++;
        }
    }

    if (NULL != line_buffer)
    {
        free(line_buffer);
        line_buffer = NULL;
    }
    if (NULL != aux_buffer)
    {
        free(aux_buffer);
        aux_buffer = NULL;
    }
    close(fd);

}

void get_and_execute_command_line(struct user_and_dir user_and_direc)
{
    char *line_buffer, *pch, *aux_buffer;
    int invalid = 0;

    line_buffer = NULL;
    aux_buffer = NULL;

    line_buffer = (char*)malloc(sizeof(char) * 1024);
    aux_buffer = (char*)malloc(sizeof(char) * 1024);

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

    do
    {
        scanf("%c", &line_buffer[0]);
        scanf("%[^\n]s", line_buffer);

        invalid = 0;
        strncpy(aux_buffer, line_buffer, 1024);

        pch = strtok(line_buffer, " ");
        while (pch != NULL)
        {
            if (strcmp(pch, "INFO") == 0)
            {
                invalid++;
                pch = strtok(NULL, " ");
                info(pch);
            }
            if (strcmp(pch, "SECT_DISPLAY") == 0)
            {
                char *file_path_for_display;

                file_path_for_display = NULL;
                pch = strtok(NULL, " ");
                if (pch != NULL)
                {
                    file_path_for_display = (char *)malloc(sizeof(char) * strlen(pch));
                    memmove(file_path_for_display, pch, strlen(pch));
                    pch = strtok(NULL, " ");
                    if (pch != NULL)
                    {
                        sect_display(file_path_for_display, pch);
                    }

                    if (NULL != file_path_for_display)
                    {
                        free(file_path_for_display);
                        file_path_for_display = NULL;
                    }
                }
            }

            if (strcmp(pch, "SECT_HASH") == 0)
            {
                char *file_path_for_display;

                file_path_for_display = NULL;
                pch = strtok(NULL, " ");
                if (pch != NULL)
                {
                    file_path_for_display = (char *)malloc(sizeof(char) * strlen(pch));
                    memmove(file_path_for_display, pch, strlen(pch));
                    pch = strtok(NULL, " ");
                    if (pch != NULL)
                    {
                        sect_hash(file_path_for_display, pch);
                    }

                    if (NULL != file_path_for_display)
                    {
                        free(file_path_for_display);
                        file_path_for_display = NULL;
                    }
                }
            }

            if (strcmp(pch, "SEARCH") == 0)
            {
                invalid++;
                pch = strtok(NULL, " ");
                if (pch != NULL)
                {
                    char *file_name;

                    file_name = NULL;
                    file_name = (char*)malloc(sizeof(char) * strlen(pch));
                    strncpy(file_name, pch, strlen(pch) + 1);

                    pch = strtok(NULL, " ");
                    if (pch != NULL)
                    {
                        if (strcmp(pch, "-R") == 0)
                        {
                            pch = strtok(NULL, " ");
                            if (NULL == pch)
                            {
                                search_files_and_sections(user_and_direc.USER_DIR, file_name, NULL, 0, 1);
                            }
                            else
                            {
                                char *sec_name;
                                sec_name = NULL;
                                sec_name = (char*)malloc(sizeof(char) * strlen(pch));
                                strncpy(sec_name, pch, strlen(pch) + 1);
                                pch = strtok(NULL, " ");
                                if (pch != NULL)
                                {
                                    search_files_and_sections(user_and_direc.USER_DIR, file_name, sec_name, atoi(pch), 1);
                                }

                                if (NULL != sec_name)
                                {
                                    free(sec_name);
                                    sec_name = NULL;
                                }
                            }
                        }
                        else
                        {
                            char *sec_name;
                            sec_name = NULL;
                            sec_name = (char*)malloc(sizeof(char) * strlen(pch));
                            strncpy(sec_name, pch, strlen(pch) + 1);
                            pch = strtok(NULL, " ");
                            if (pch != NULL)
                            {
                                search_files_and_sections(user_and_direc.USER_DIR, file_name, sec_name, atoi(pch), 0);
                            }

                            if (NULL != sec_name)
                            {
                                free(sec_name);
                                sec_name = NULL;
                            }
                        }
                    }
                    else
                    {
                        search_files_and_sections(user_and_direc.USER_DIR, file_name, NULL, 0, 0);
                    }

                    if (NULL != file_name)
                    {
                        free(file_name);
                        file_name = NULL;
                    }
                }
            }

            if (strcmp(pch, "SCAN_FILE") == 0)
            {
                invalid++;
                pch = strtok(NULL, " ");
                if (pch != NULL)
                {
                    char *file_name;

                    file_name = NULL;
                    file_name = (char*)malloc(sizeof(char) * MAX_PATH_LEN);
                    strncpy(file_name, pch, strlen(pch)  + 1);

                    file_name = create_path(user_and_direc, file_name);

                    scan_file(file_name);
                    
                    if (section_header != NULL)
                    {
                        free(section_header);
                        section_header = NULL;
                    }
                }
            }

            if (strcmp(pch, "SCAN_DIR") == 0)
            {
                invalid++;
                pch = strtok(NULL, " ");
                if (pch != NULL)
                {
                    char *dir_name;

                    dir_name = NULL;
                    dir_name = (char*)malloc(sizeof(char) * MAX_PATH_LEN);
                    strncpy(dir_name, pch, MAX_PATH_LEN);

                    printf("%s\n", pch);
                    printf("%s\n", dir_name);
                    dir_name = create_path(user_and_direc, dir_name);

                    scan_dir(dir_name);
                    if (section_header != NULL)
                    {
                        free(section_header);
                        section_header = NULL;
                    }
                }
                else
                {
                    char *dir_name;

                    dir_name = NULL;
                    dir_name = (char*)malloc(sizeof(char) * MAX_PATH_LEN);
                    dir_name = create_path(user_and_direc, NULL);

                    scan_dir(dir_name);
                    if (section_header != NULL)
                    {
                        free(section_header);
                        section_header = NULL;
                    }
                }
            }

            if (strcmp(pch, "CLEAN_FILE") == 0)
            {
                invalid++;
                pch = strtok(NULL, " ");
                if (pch != NULL)
                {
                    char *file_name;
                    char *aux;

                    aux = NULL;
                    aux = (char*)malloc(sizeof(char) * (strlen(pch) + 1));
                    if (aux == NULL)
                    {
                        ERR_MSG("Malloc failed");
                        exit(MALLOC_FAILED);
                    }

                    strncpy(aux, pch, strlen(pch) + 1);

                    file_name = create_path(user_and_direc, aux);

                    clean_file(file_name);

                    if (section_header != NULL)
                    {
                        free(section_header);
                        section_header = NULL;
                    }
                }
            }
            pch = strtok(NULL, " ");
        }
        if (invalid == 0)
        {
            printf("INVALID COMMAND!\n");
        }

    } while (strcmp(line_buffer, "EXIT"));
    if (strcmp(line_buffer, "EXIT") == 0)
    {
        printf("Program ends !\n");
        exit(10);
    }
}

void authenticate(struct user_and_dir *users_and_dirs, int n)
{
    char user_name[128];
    int i, ok;

    ok = 0;

    printf("Introduce your username !\nYour username mustn't exceed 30 characters in length!\n");
    scanf("%s", user_name);
    if (strlen(user_name) > 30)
    {
        printf("Your username is too long!\n");
        exit(INVALID_USER);
    }

    for (i = 0; i < n; i++)
    {
        if (check_for_equality(user_name, (uint8_t *)users_and_dirs[i].USER_NAME) != 0)
        {
            ok++;
            user_and_dir_final = users_and_dirs[i];
        }
    }

    if (ok > 1)
    {
        ERR_MSG("ERROR (a user is assigned to several directories)");
        exit(USER_ASSIGNED_TO_SEVERAL_DIRECTORIES);
    }
    else if (ok == 0)
    {
        ERR_MSG("ERROR (INVALID user)");
        exit(INVALID_USER);
    }
    else
    {
        get_and_execute_command_line(user_and_dir_final);
    }
}

int main(int argc, char *argv[])
{
    char message[] = "Implement OS Lab Assigment 1. File System Module!\n";
    struct user_and_dir *users_and_directories;
    int number_of_users_and_dirs;

    users_and_directories = NULL;
    number_of_users_and_dirs = 0;

    semaphore_id = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);

    semctl(semaphore_id, 0, SETVAL, 1);

    users_and_directories = (struct user_and_dir *)malloc(sizeof(struct user_and_dir) * 1024);

    if (NULL == users_and_directories)
    {
        ERR_MSG("ERROR (malloc failed)");
        exit(1);
    }
    printf("%s", message);

    if (argc != 2) {
        printf("USAGE: %s Config_file\n", argv[0]);
        exit(1);
    }

    if (argv[1] == NULL)
    {
        ERR_MSG("ERROR (incorrect argument for config_file)");
        exit(2);
    }
    validate_config_file(argv[1], users_and_directories);

    while (users_and_directories[number_of_users_and_dirs].USER_DIR[0])
    {
        printf("%s %s\n", users_and_directories[number_of_users_and_dirs].USER_DIR, users_and_directories[number_of_users_and_dirs].USER_NAME);
        number_of_users_and_dirs++;
    }

    authenticate(users_and_directories, number_of_users_and_dirs);

    return (0);
}