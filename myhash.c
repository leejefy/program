#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_FILE_PATH "./en.h"

#define START_MARK "[["	
#define END_MARK  "]]"
#define EQUAL_MASK "="

struct keyword *config_head[257] = { NULL };

#define HEAD_TABLE_SIZE   sizeof(config_head)/sizeof(config_head[0])


struct keyword{
	char *name;
	char *value;
	//int flag;
	struct keyword *next;
};

struct keyword *head = NULL;

//struct keyword *word_head[257] = { NULL };


static int hash(const char *s)
{
	int hash = 0;

	while (*s)
		hash = 31 * hash + *s++;

	return hash;
}

struct keyword *keyword_match(const struct keyword *pinfo)
{
	int i;
	struct keyword *entry = NULL;
	const char *val = NULL;
	int config_debug = 1;
	int config_counter[257];
			printf("2222 \n");
			
	entry = (struct keyword *)malloc(sizeof(*entry));
	
	memset(entry, 0 ,sizeof(entry));
	if( entry == NULL ){
		return NULL;	
	}
			printf("3333 \n");
	memcpy(entry,pinfo,sizeof(entry));
		printf("444 \n");
	printf("name : %s value :%s \n", entry->name,entry->value);

	//i = hash(entry->name) % HEAD_TABLE_SIZE;
	return 0;
}


void dump(name, value)
{
	type *p = head;
	while(p){
		printf("[%s]=%s\n", p->name, p->value);	
		p  = p->next;
	}
}




int main()
{
	
push("ddd", "value");
push("ddd", "value");
push("ddd", "value");
push("ddd", "value");
push("ddd", "value");
push("ddd", "value");

dump(head);

free(head);

}
void config_dump(char *name, char *value)
{
	struct keyword *entry = head;
	while(entry){
		printf("[%s] = %s \n",entry->name,entry->value);
		entry = entry->next;	
	}
}


void config_push(char *name,char *value)
{
	struct keyword *entry = malloc(sizeof(entry));
	strcpy(entry->name,name);
	entry->next = head ;
	head = entry;
}


/* [[aaaa]] = [[ bbbb ]] */
char *read_config(char *info)
{
		struct keyword *entry = NULL;
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
		printf("name: %s  \n", name); 
	
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
		
		printf("value: %s  \n", value);
		
		config_push(name, value);
		
		return 0;
}

int main(int argc, char** argv)
{
	// set fp to open file 
	// show all hash table
	// please input word
	// find the location in the array ,through the hash.
	// display the word you find 
	// free the fp
	FILE *fp;
//	char *buffer = strdup("ddd--=sd';.[]a[][[][[dfdasdf]]gfsdew231/.m,][./[u][890870989p']d]dd87[sf[[]ds]p[;'d]d]f[d]]d[fsafwe]]]sdf]]sad]]");
	char buffer[1024];
	
	fp = fopen(TEST_FILE_PATH, "r");

	if(fp) {
		while(!feof(fp)) {// finish then 1:exit 
			if (fgets(buffer, sizeof(buffer), fp)){
	 			read_config(buffer);
	 	
	 		//	keyword_match(buffer);
			}
		}
		fclose(fp);
	} else {
		fprintf(stderr, "Fail to open log file!\n");
	}
 return 0;
}
