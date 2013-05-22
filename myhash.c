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
	struct config_entry *next;
};

//struct config_entry *head = NULL;

struct config_entry *head[200] = {NULL};

#define hash_table_size sizeof(head)/sizeof(head[0])

int config_count[200];

//void config_free(struct config_entry *head);
void config_free(void);

static struct config_entry *config_dump(struct config_entry *head ,const char *name);

void config_push(char *name,char *value);

void free_one(void *p)
{
	printf("<---- free mem %p \n",p);	
	free(p);
}
/*
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

static struct config_entry *config_dump(struct config_entry *head ,const char *name)
{
	struct config_entry *entry = head;

	while(entry){
		if (!strcmp(name, entry->name)){
//			printf("[%s] = %s \n",entry->name,entry->value);
			return entry;
		}
		entry = entry->next;		
	}	
	return NULL;
}

void config_push(char *name,char *value)
{
	struct config_entry *entry;
	int i;

	entry = (struct config_entry *)malloc(sizeof(	struct config_entry));

	printf("------>new mem:%p\n", entry);		

	entry->name = strdup(name); // malloc(strlen(name) + 1); strcpy(entry->name, name)
	printf("------>new mem:%p\n", entry->name);
				
	entry->value = strdup(value);
	printf("------>new mem:%p\n", entry->value);	

	i = hash(entry->name)%hash_table_size;
	
	config_count[i]++;
	printf("config table---> %d ( %d ) ,[ %s ] \n", i,config_count[i],entry->name );

	entry->next = head[i];
	head[i] = entry;
	config_dump(head[i],entry->name);
}

void config_free(void)
{
	struct config_entry *p = NULL ,*q;
	int i;
//	i = hash(p->name)%hash_table_size;
	for (i = 0; i < hash_table_size; i ++){
		p = head[i];
		while(p){
			q = p->next;			
			if ( p->value!= NULL ) { free_one(p->value); }
			if ( p->name!= NULL ) { free_one(p->name); }
			free_one(p); 
			p = q;		
		}	
//		head[i] = NULL;
	}
}


char *read_config(char *info)
{
//	struct keyword *entry = NULL;
		char *end_pos;
		char *start_pos;
		char *sp;
		char *name,*value;
		/*
		   | -- [[  ]]  [[  ]] |		                 
		*/
		sp =strdup(info);
	//	printf("info :%s \n" ,sp);
		start_pos = strstr(sp,START_MARK); // [[^
		if( start_pos == NULL ){
			printf("Invalid value 1!\n");	
			return 0;		
		}
		start_pos += strlen(START_MARK); // [[^
		
		end_pos = strstr(start_pos,END_MARK); // ]]^

		if( end_pos == NULL ){
			printf("Invalid value 2!\n");	
			return 0;
		}
		*end_pos = '\0';
		/*
		   | -- [[  ]]\0  [[  ]] |		                 
		     end_pos  ^
		*/
		
		name = start_pos;
//		printf("name: %s  \n", name); 
	
		start_pos = end_pos;
		/*
		   | -- [[  ]]\0 ]] [[  ]] [[ ]]  [[  ]] |		                 
		     start_pos ^
		     p = info
		     get_next_value(p );
		     p + x;
		     get_next_value(p);
		     
		*/
		sp = end_pos + 1;
		start_pos = strstr(sp,START_MARK); //[[^
		if( start_pos == NULL ){
			printf("Invalid value 3! \n");	
			return 0;
		}
		start_pos += strlen(START_MARK);
		
		end_pos = strstr(start_pos,END_MARK); // ]]^
	//	printf("%p - %p  = %d\n", start_pos, end_pos, end_pos - start_pos);
		if( end_pos == NULL ){
			printf("Invalid value 4! \n");	
			return 0;
		}
		*end_pos = '\0';
		
		value = start_pos;
		
//	printf("value: %s  \n", value);
		
		config_push(name, value);
	
		return 0;
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
	
//	config_push("ddd", "value");// malloc(config_entry) malloc(name) malloc(value)
//  config_push("eeee", "valueddd");
//  config_push("aaaaa", "valuessss");

	//config_free(head);
	
	FILE *fp;

	char buffer[1024];
	
	fp = fopen(TEST_FILE_PATH, "r");

	if(fp) {
		while(!feof(fp)) {// finish then 1:exit 
			if (fgets(buffer, sizeof(buffer), fp)){
	 			read_config(buffer);
			}
		}
		config_free();
		fclose(fp);
	} else {
		fprintf(stderr, "Fail to open log file!\n");
	}

	return 0;
}
