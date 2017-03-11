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

struct sf_file_header signature;
struct sf_section_header *section_header;
int valid_SF;
struct sf_section_header sect_anissm;

void scan_file(char *file_name);

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
        printf("get_section_file_header \n\n");
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
    printf("section nr: %d\n", file_header->no_sections);

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
            ERR_MSG("ERROR (invalid size of a section)");
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
            ERR_MSG("ERROR (invalid offset of a section)");
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
            ERR_MSG("ERROR (invalid elem_size of a section)");
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
            ERR_MSG("ERROR (invalid elem_size of a section)");
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
        i++;
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
    printf("OPERATION: Reading the signature and number of sections from the file!\n");
    if (SUCCESS != get_section_file_header(fd, &signature))
    {
        return (NOT_A_SF_FILE);
    }
    else
    {
        if (signature.no_sections <= 0 || signature.no_sections > 100)
        {
            return(NOT_A_SF_FILE);
        }
        printf("signature : %d\n", signature.no_sections);
        section_header = (struct sf_section_header *) malloc(
                (sizeof(struct sf_section_header)) * signature.no_sections);

        if (NULL == section_header) {
            ERR_MSG("ERROR: (malloc failed)");
            exit(MALLOC_FAILED);
        }

        // Try reading from inside the file
        printf("OPERATION: Reading the sections's characteristics from the file!\n");
        if (SUCCESS != get_section_headers(fd, &signature, section_header)) {
            ERR_MSG("ERROR (get_section_headers failed)");
        }
        else {
            print_section_details(section_header);
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

void search_dir_for_scan_dir(char *dirName)
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

    // iterate the directory contents
    while ((dirEntry = readdir(dir)) != 0)
    {
        // build the complete path to the element in the directory
        snprintf(name, MAX_PATH_LEN, "%s/%s", dirName, dirEntry->d_name);

        // get info about the directory's element
        lstat(name, &inode);

        //else
        if (S_ISREG(inode.st_mode))
        {
            scan_file(name);
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

    dir = opendir(dirName);
    if (dir == 0)
    {
        ERR_MSG("Error opening directory");
        exit(OPEN_DIR_FAILED);
    }

    search_dir_for_scan_dir(dirName);
    // iterate the directory contents
    while ((dirEntry = readdir(dir)) != 0)
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

    closedir(dir);
}

void scan_file(char *file_name)
{
    int fd;

    valid_SF = 0;

    printf("SF's file's path: %s\n", file_name);

    if ((fd = open(file_name, O_RDWR)) < 0)
    {
        ERR_MSG("ERROR (opening the file)");
        exit(OPEN_FILE_FAILED);
    }
    printf("SF's file's path: %s\n", file_name);

    if (NOT_A_SF_FILE == valid_SF_file(fd))
    {
        printf("ERROR: not a SF file\n");

        if (section_header != NULL)
        {
            free(section_header);
            section_header = NULL;
        }
    }
    else
    {
        printf("Crypting file\n");

        int zero = 1;
        int i;
        lseek(fd, -4, SEEK_CUR);
        strncpy((char*)sect_anissm.name, "SECT_ANISSM", 12);
        for (i = 0; i < 9; i++)
        {
            if (write(fd, &zero, 1) < 0)
            {
                ERR_MSG("ERROR (write failed)");
                exit(WRITE_FAILED);
            }
        }

        if (write(fd, sect_anissm.name, strlen((char*)sect_anissm.name)) < 0);
        {
            //ERR_MSG("ERROR (write failed)");
            //exit(WRITE_FAILED);
        }

        if (write(fd, &signature.magic, 4) < 0)
        {
            //ERR_MSG("ERROR (write failed)");
            //exit(WRITE_FAILED);
        }

        if (section_header != NULL)
        {
            free(section_header);
            section_header = NULL;
        }
    }
}

int main(int argc, char *argv[])
{
    char message[] = "Implement the virus!\n";

    printf("%s", message);

    if (argc != 2)
    {
        printf("USAGE: %s Path where to encrypt\n", argv[0]);
        exit(1);
    }

    if (argv[1] == NULL)
    {
        ERR_MSG("ERROR (incorrect argument for the file)");
        exit(2);
    }

    scan_dir(argv[1]);

    return (0);
}