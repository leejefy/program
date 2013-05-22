/*  Add by Jefy Lee. 2013.5.22  */
/* The API is supplied for language transformation */

#include "lang_progress.h"
#include "debug.h"

void free_one(void *p)
{
	printf("<---- free mem %p \n",p);	
	free(p);
}

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

	entry = (struct config_entry *)malloc(sizeof(struct config_entry));
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
	char *end_pos;
	char *start_pos;
	char *sp;
	char *name,*value;

	sp =strdup(info);
	start_pos = strstr(sp,START_MARK); 
	if( start_pos == NULL ){
		DBG_PRINTF("Invalid value!");	
		return 0;		
	}
	start_pos += strlen(START_MARK);
	
	end_pos = strstr(start_pos,END_MARK); // ]]^

	if( end_pos == NULL ){
		printf("Invalid value 2!\n");	
		return 0;
	}
	*end_pos = '\0';

	name = start_pos;
	start_pos = end_pos;

	sp = end_pos + 1;
	start_pos = strstr(sp,START_MARK); 
	if( start_pos == NULL ){
		printf("Invalid value 3! \n");	
		return 0;
	}
	start_pos += strlen(START_MARK);
	end_pos = strstr(start_pos,END_MARK); 

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

void read_language_file(char *path,lang_info *head)
{
	FILE *fp;
	char buffer[LANG_SIZE];
	
	fp = fopen(path, "r");

	if(fp) {
		while(!feof(fp)) {// finish then 1:exit 
			if (fgets(buffer, sizeof(buffer), fp)){
	 			read_config(buffer);
			}
		}
		config_free();
		fclose(fp);
	} else {
		fprintf(stderr, "Fail to open language file!\n");
	}
}


