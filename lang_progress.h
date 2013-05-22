#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct lang_info{
	char *name;
	char *value;
	struct lang_info *next;
};

#define START_MARK "[["	
#define END_MARK  "]]"
#define EQUAL_MASK "="
#define LANG_SIZE 256
#define hash_table_size sizeof(head)/sizeof(head[0])

int config_count[200];


void read_language_file(char *path,lang_info *head);
int system_language(void);
char *find_in_file(char_t **argv , char content);
