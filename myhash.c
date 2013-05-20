#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_FILE_PATH "./en.h"

#define START_MARK "[["	
#define END_MARK  "]]"
#define EQUAL_MASK "="

struct config_entry{
	char *name;
	char *value;
	//int flag;
	struct config_entry *next;
};

//struct config_entry *head = NULL;

struct config_entry *head[200] = NULL;

#define hash_table_size sizeof(head)/sizeof(head[0])

int config_count[200];

/*
void free_one(void *p)
{
	printf("<---- free mem %p \n",p);	
	free(p);
}

void my_free(struct config_entry *p)
{
	free_one(p->value);
	free_one(p->name);
	free_one(p);
}
*/


static int hash(const char *s)
{
	int hash = 0;
	
	while (*s)
		hash = 31 * hash + *s++;
	return hash;
}

/*
struct config_entry *sort_out(struct config_entry *head)
{
	int i;
	struct config_entry *entry;
	entry = (struct config_entry *)malloc(sizeof(*entry));
	if (entry == NULL){
		return NULL;
	}
	memcpy(entry, head , sizeof(*entry));
	
	i = hash(entry->name)%hash_table_size;
	
	config_count[i]++;
	printf("config table---> %d ( %d ) ,[ %s ]", i,config_count[i],entry->name );
	
	entry->next = head[i];
	head[i] = entry;
	return entry;
}
*/

void config_dump( struct config_entry *head )
{
	struct config_entry *entry = head;
	while(entry){
		printf("[%s] = %s , %d \n",entry->name,entry->value,hash(entry->name));
		entry = entry->next;	
	}
}



void config_push(char *name,char *value)
{
	struct config_entry *entry;
	int i;

	entry = (struct config_entry *)malloc(sizeof(	struct config_entry));

//	printf("------>new mem:%p\n", entry);		

	entry->name = strdup(name); // malloc(strlen(name) + 1); strcpy(entry->name, name)
	printf("------>new mem:%p\n", entry->name);
				
	entry->value = strdup(value);
//	printf("------>new mem:%p\n", entry->value);	

	i = hash(entry->name)%hash_table_size;
	
	entry->next = head[i];
	head[i] = entry;
}

void config_free(struct config_entry *head)
{
	struct config_entry *p = head ,*q;

	while(p){
		q = p->next;			
		if ( p->value!= NULL ) { free(p->value); }
		if ( p->name!= NULL ) { free(p->name); }	
		free(p); 
		p = q;		
	}	
}

	// set fp to open file 
	// show all hash table
	// please input word
	// find the location in the array ,through the hash.
	// display the word you find 
	// free the fp

int main(int argc, char** argv)
{
//	struct config_entry *p, *next;
	
	config_push("ddd", "value");// malloc(config_entry) malloc(name) malloc(value)
  config_push("eeee", "valueddd");
  config_push("aaaaa", "valuessss");

	//config_dump(head);
	//sort_out(head);
	//config_free(head);

	return 0;
}
