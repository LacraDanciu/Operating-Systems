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

//define constants for my program

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

//global variables
int number_of_files;
struct sf_file_header signature;
struct sf_section_header *section_header;

void print_section_details(struct sf_section_header *section_header);

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
	printf("SF signature: ");
	printf("%X\n", file_header->magic);

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

	printf("SF's number of sections: ");
	printf("%X\n", file_header->no_sections);

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

	while (i != file_header->no_sections)
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
			printf("Section number: %d", i);
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
			printf("Section number: %d", i);
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
			printf("Section number: %d", i);
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
			printf("Section number: %d", i);
			errno = EINVAL;
			return errno;
		}

		if ((bytesRead = read(fd, section_header[i].name, section_header[i].name_size)) < 0)
		{
			ERR_MSG("ERROR (reading from inside the file)");
			errno = READ_FILE_FAILED;
			return errno;
		}

		i++;

	}
	errno = SUCCESS;
	return errno;
}

int check_for_equality(char *first, uint8_t *second)
{
	int i, count;

	i = 0;
	count = 0;

	printf("%d\n", (int)strlen(first));
	printf("%d\n", (int)strlen((char *)second));

	if (first[i] == (char)second[i] && (strlen(first) == strlen((char *)second)))
	{
		while ((first[i] == (char)second[i]) && (i < strlen(first)))
		{
			count++;
			i++;
		}
	}

	if (count == strlen(first))
	{
		return(1);
	}

	return(0);
}

int valid_SF_file(int fd)
{
	int bytesRead;
	uint32_t magic;
	uint32_t value;

	value = 0xB612B612;
	section_header = NULL;

	// Try reading from inside the file
	printf("OPERATION: Reading the signature and number of sections from the file!\n");
	if (SUCCESS != get_section_file_header(fd, &signature))
	{
		ERR_MSG("ERROR: not a SF file");
	}

	section_header = (struct sf_section_header *)malloc((sizeof(struct sf_section_header) - 256)*signature.no_sections);

	if (NULL == section_header)
	{
		ERR_MSG("ERROR: (malloc failed)");
		exit(MALLOC_FAILED);
	}

	// Try reading from inside the file
	printf("OPERATION: Reading the sections's characteristics from the file!\n");
	if (SUCCESS != get_section_headers(fd, &signature, section_header))
	{
		ERR_MSG("ERROR (get_section_headers failed)");
	}
	else
	{
		print_section_details(section_header);
	}

	if ((bytesRead = read(fd, &magic, 4)) < 0)
	{
		ERR_MSG("ERROR (reading from inside the file)");
	}

	if (magic != value)
	{
		return(NOT_A_SF_FILE);
	}
	else
	{
		return(VALID_SF_FILE);
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

		// test the type of the directory's element
		//if (S_ISDIR(inode.st_mode))

		//else
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
							printf("heehehe\n");
							if (check_for_equality(section_name, section_header[i].name) != 0)
							{
								printf("hddjd\n");
								if (section_size != 0)
								{
									printf("hemwow\n");
									if (section_header[i].size >= section_size)
									{
										printf("%s\n", searched_name);
										printf("%s\n", section_header[i].name);
										printf("%d\n", section_header[i].size);
										printf("djdjdjjdjdjdhehe\n");
										ok = 1;
									}
								}
								else if (section_size == 0)
								{
									printf("%s\n", searched_name);
									printf("%s\n", section_header[i].name);
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

	printf("%s\n", section_data);

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

	while (i != signature.no_sections)
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
		exit(NOT_A_SF_FILE);
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
		printf("bdld");
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
		exit(NOT_A_SF_FILE);
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
				ERR_MSG("ERROR: not a SF file or not a TEXT section\n");
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
		exit(NOT_A_SF_FILE);
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
			ERR_MSG("ERROR: not a SF file or not a BINARY section\n");
		}
	}
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
		memmove(aux_buffer, line_buffer, 1024);

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
					memcpy(from_config[users_and_dirs].USER_DIR, pch, strlen(pch));
					ok = 1;
				}
				else
				{
					ok = 0;
				}
			}
			if ((number == 2) && (ok == 1) && (pch[0] != '\n'))
			{

				memmove(from_config[users_and_dirs].USER_NAME, pch, strlen(pch));
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

		memmove(aux_buffer, line_buffer, 1024);

		pch = strtok(line_buffer, " ");
		while (pch != NULL)
		{
			if (strcmp(pch, "INFO") == 0)
			{
				pch = strtok(NULL, " ");
				info(pch);
			}
			//			if (strcmp(pch, "SECT_DISPLAY") == 0)
			//			{
			//				char *file_path_for_display;
			//
			//				file_path_for_display = NULL;
			//				pch = strtok(NULL, " ");
			//				if (pch != NULL)
			//				{
			//					file_path_for_display = (char *)malloc(sizeof(char) * strlen(pch));
			//					memmove(file_path_for_display, pch, strlen(pch));
			//					pch = strtok(NULL, " ");
			//					if (pch != NULL)
			//					{
			//						sect_display(file_path_for_display, pch);
			//					}
			//
			//					if (NULL != file_path_for_display)
			//					{
			//						free(file_path_for_display);
			//						file_path_for_display = NULL;
			//					}
			//				}
			//			}
			//
			//			if (strcmp(pch, "SECT_HASH") == 0)
			//			{
			//				char *file_path_for_display;
			//
			//				file_path_for_display = NULL;
			//				pch = strtok(NULL, " ");
			//				if (pch != NULL)
			//				{
			//					file_path_for_display = (char *)malloc(sizeof(char) * strlen(pch));
			//					memmove(file_path_for_display, pch, strlen(pch));
			//					pch = strtok(NULL, " ");
			//					if (pch != NULL)
			//					{
			//						sect_hash(file_path_for_display, pch);
			//					}
			//
			//					if (NULL != file_path_for_display)
			//					{
			//						free(file_path_for_display);
			//						file_path_for_display = NULL;
			//					}
			//				}
			//			}
			if (strcmp(pch, "SEARCH") == 0)
			{
				pch = strtok(NULL, " ");
				if (pch != NULL)
				{
					char *file_name;

					file_name = NULL;
					file_name = (char*)malloc(sizeof(char) * strlen(pch));
					memmove(file_name, pch, strlen(pch));

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
								memmove(sec_name, pch, strlen(pch));
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
							memmove(sec_name, pch, strlen(pch));
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
			pch = strtok(NULL, " ");
		}

		scanf("%[^\n]s", line_buffer);
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
	struct user_and_dir aux;
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
		printf("%s   ", user_name);
		printf("%s\n", users_and_dirs[i].USER_NAME);
		if (check_for_equality(user_name, (uint8_t *)users_and_dirs[i].USER_NAME) != 0)
		{
			ok++;
			aux = users_and_dirs[i];
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
		get_and_execute_command_line(aux);
	}

}

int main(int argc, char *argv[])
{
	char message[] = "Implement OS Lab Assigment 1. File System Module!\n";
	struct user_and_dir *users_and_directories;
	int number_of_users_and_dirs;

	users_and_directories = NULL;
	number_of_users_and_dirs = 0;

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
		printf("%s %s", users_and_directories[number_of_users_and_dirs].USER_DIR, users_and_directories[number_of_users_and_dirs].USER_NAME);
		number_of_users_and_dirs++;
	}

	authenticate(users_and_directories, number_of_users_and_dirs);
	/// not every function works..
	/// the code is written for them, but I couldn't check it for all cases.

	return (0);
}