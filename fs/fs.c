/**
 * @author anway mukherjee <anwaym@vt.edu>
 */

#include <hermit/stdio.h>
#include <hermit/malloc.h>
#include <hermit/spinlock.h>
#include <hermit/memory.h>
#include <hermit/logging.h>
#include <asm/page.h>
#include <hermit/fs.h>
#include <hermit/string.h>

struct fs_Dentry curr_dir;
struct fs_File curr_file;


size_t mk_fs(size_t part_addr)
{
	struct fs_Superblk *super;
	struct fs_Inode *node;
	
	size_t total_superBlock = sizeof(struct fs_Superblk);
	size_t total_inodeBlock = sizeof(struct fs_Inode) * NUMBER_INODES;
	size_t total_fileBlock = TOTAL_RAMDISK_SPACE - (total_inodeBlock + total_superBlock);
	size_t total_number_fblocks = total_fileBlock / sizeof(struct FileBlock_list_node);



	super = part_addr;
	//LOG_INFO("Root start address: %d \n", super);
	super->partition = part_addr;
	//LOG_INFO("partition var address: %d \n", &(super->partition));
	super->total_size = total_superBlock;
	//LOG_INFO("total_size var address: %d \n", &(super->total_size));
	super->block_size = total_fileBlock;
	//LOG_INFO("block_size var address: %d \n", &(super->block_size));
	super->inode_size = 0;//total_inodeBlock;
	//LOG_INFO("inode_size var address: %d \n", &(super->inode_size));
	super->pwd = (part_addr + sizeof(struct fs_Superblk));
	//LOG_INFO("pwd var address: %d \n", &(super->pwd));
	strcpy(super->type,"anwayFS");	
	//LOG_INFO("type var address: %d \n", &(super->type));
	super->pfd = 0;



	for(int i = 0; i< NUMBER_INODES; i++ ){
		if(i== 0){
			super->free_inode_map[i] = 0;				
		}		
		else{
			super->free_inode_map[i] = 1;		
		}
	}


	//LOG_INFO("free_inode_map var address: %d \n", &(super->free_inode_map));

	for(int i = 0; i< NUMBER_FILES; i++ ){
		super->free_fsblock_map[i] = 1;	
	}
	//LOG_INFO("free_fsblock_map var address: %d \n", &(super->free_fsblock_map));
	
	node = super->pwd;
	//LOG_INFO("inode start address: %d \n", node);
	
	strcpy(node->Inode_name,"/");	
	strcpy(node->Inode_path,"/");
	strcpy(node->Inode_type,"D");

	/*LOG_INFO("Name of dir stored: %s \n", node->Inode_name);
	LOG_INFO("Path of dir stored: %s \n", node->Inode_path);
	LOG_INFO("Type of dir stored: %s \n", node->Inode_type);		*/

	node->Inode_index = 0;
	node->address = super->pwd;
	node->size_max = 0;
	node->Inode_size = 0;	
	node->parent = NULL;
	for(int i = 0; i<NUMBER_INODES; i++ )
	{
		node->child[i] = NULL;
	}
	node->fcontent_buf_head = NULL;
	node->fcontent_buf_tail = NULL;

	return (size_t) super->pwd;
}


struct fs_Dentry* fs_list(size_t partition)
{
	//TODO: will have to add check to confirm the pwd Inode is in fact a dentry
	struct fs_Superblk *super;
	struct fs_Inode *node;
	
	memset(&curr_dir, 0x00, sizeof(struct fs_Dentry));

	//struct fs_Dentry *curr_dir = (struct fs_Dentry *) malloc(sizeof(struct fs_Dentry ));	
	for(int i = 0; i<NUMBER_DIRS; i++){	
		curr_dir.dir_child[i] = NULL;			
	}

	super = partition;	
	node = 	super->pwd;
	curr_dir.location = super->pwd;
	strcpy(curr_dir.dir_name, node->Inode_name);
	strcpy(curr_dir.dir_path, node->Inode_path);
	curr_dir.dir_parent = node->parent;	
	//LOG_INFO("Name of dir: %s \n", curr_dir.dir_name);
	//LOG_INFO("Path of dir: %s \n", curr_dir.dir_path);
	
	for(int i = 0; i<NUMBER_DIRS; i++){	
		curr_dir.dir_child[i] = node->child[i];			
	}

	return (&curr_dir);
}

size_t fs_makedir(size_t part_addr, size_t root_addr, char *name)
{
	struct fs_Superblk *super;
	struct fs_Inode *node, *node_stub;
	super = part_addr;
	int i;
	for(i = 0; i< NUMBER_INODES; i++ ){
		if(super->free_inode_map[i] == 1){
			break;	
		}
	}
	
	node = 	root_addr + (sizeof(struct fs_Inode) * (i));
	super->free_inode_map[i] = 0;
	node_stub = super->pwd;

	//LOG_INFO("value of i: %d \n", i);
	//LOG_INFO("Name of curr dir: %s \n", node_stub->Inode_name);

	strcpy(node->Inode_name,name);	
	strcpy(node->Inode_path, node_stub->Inode_path);
	int k = 0;
	int j;
	for(j = strlen(node_stub->Inode_path); j < (strlen(node_stub->Inode_path)+strlen(name)); j++)
	{	
		node->Inode_path[j] = name[k];
		k++;

	}

	node->Inode_path[j] = '/';

	//strcat(node_stub->Inode_path, name);	
	
	strcpy(node->Inode_type,"D");

	/*LOG_INFO("Name of dir stored: %s \n", node->Inode_name);
	LOG_INFO("Path of dir stored: %s \n", node->Inode_path);
	LOG_INFO("Type of dir stored: %s \n", node->Inode_type);		*/

	node->Inode_index = i;
	
	node->address = root_addr + (sizeof(struct fs_Inode) * (i));
	node->size_max = 0;
	node->Inode_size = 0;	
	node->parent = super->pwd;
	int flag = 0;
	for(int i = 0; i<NUMBER_INODES; i++ )
	{
		if(node_stub->child[i] == NULL)
		{
			node_stub->child[i] = node->address;
			flag = 1;
		}

		if(flag)
			break;
		
	}


	
	for(int i = 0; i<NUMBER_INODES; i++ )
	{
		node->child[i] = NULL;
	}
	node->fcontent_buf_head = NULL;
	node->fcontent_buf_tail = NULL;
	return 0;

}


struct fs_Dentry* fs_change_dir(size_t part_addr, char *name){

	struct fs_Superblk *super;
	struct fs_Inode *node, *node_stub;
	super = part_addr;
	node = super->pwd;


	for(int i =0; i<NUMBER_INODES; i++){

		if(strcmp(name,"..")==0){
			super->pwd = node->parent;	
			break;			
		}
		
		if(node->child[i]== NULL)
			break;

		else{
			node_stub = node->child[i];
			if(strcmp(node_stub->Inode_name,name)==0 && strcmp(node_stub->Inode_type,"D")==0){
				super->pwd = node_stub->address;
			}
		}		
	}

}



size_t fs_fileopen(size_t part_addr, size_t root_addr, char *name, char *mode){

	struct fs_Superblk *super;
	struct fs_Inode *node, *node_stub;

	super = part_addr;

	int i;
	for(i = 0; i< NUMBER_INODES; i++ ){
		if(super->free_inode_map[i] == 1){
			break;	
		}
	}
	
	node = 	root_addr + (sizeof(struct fs_Inode) * (i));
	super->pfd = root_addr + (sizeof(struct fs_Inode) * (i));
	super->free_inode_map[i] = 0;
	node_stub = super->pwd;

	//LOG_INFO("value of i: %d \n", i);
	//LOG_INFO("Name of cwd: %s \n", node_stub->Inode_name);

	strcpy(node->Inode_name,name);	
	strcpy(node->Inode_path, node_stub->Inode_path);

	int k = 0;
	int j;
	for(j = strlen(node_stub->Inode_path); j < (strlen(node_stub->Inode_path)+strlen(name)); j++)
	{	
		node->Inode_path[j] = name[k];
		k++;

	}

	//node->Inode_path[j] = '/';

	//strcat(node_stub->Inode_path, name);	
	
	strcpy(node->Inode_type,"F");

	/*LOG_INFO("Name of file stored: %s \n", node->Inode_name);
	LOG_INFO("Path of file stored: %s \n", node->Inode_path);
	LOG_INFO("Type of inode stored: %s \n", node->Inode_type);		*/

	node->Inode_index = i;
	
	node->address = root_addr + (sizeof(struct fs_Inode) * (i));
	
	node->size_max = 0;
	node->Inode_size = 0;	
	node->parent = super->pwd;
	int flag = 0;
	for(int i = 0; i<NUMBER_INODES; i++ )
	{
		if(node_stub->child[i] == NULL)
		{
			node_stub->child[i] = node->address;
			flag = 1;
		}

		if(flag)
			break;
		
	}


	
	for(int i = 0; i<NUMBER_INODES; i++ )
	{
		node->child[i] = NULL;
	}
	node->fcontent_buf_head = NULL;
	node->fcontent_buf_curr = NULL;
	node->fcontent_buf_tail = NULL;
	return node->Inode_index;

}

size_t fs_fileclose(size_t part_addr, char *name){

	struct fs_Superblk *super;
	super = part_addr;
	super->pfd = 0;

	memset(&curr_dir, 0x00, sizeof(struct fs_Dentry));
	memset(&curr_file, 0x00, sizeof(struct fs_File));

	return 0;
}


size_t fs_filewrite(size_t index, size_t part_addr, size_t root_addr, size_t block_start_addr){
	
	struct fs_Superblk *super;
	struct fs_Inode *node;
	struct FileBlock_list_node *curr_block, *prev_block;

	super = part_addr;
	node = super->pfd;	
	prev_block = node->fcontent_buf_curr;

	int i;
	for(i = 0; i< NUMBER_FILES; i++ ){
		if(super->free_fsblock_map[i] == 1){
			break;	
		}
	}
	

	super->free_fsblock_map[i] = 0;
	curr_block = block_start_addr + (sizeof(struct FileBlock_list_node) * (i));
	curr_block->location = block_start_addr + (sizeof(struct FileBlock_list_node) * (i));
	
	//node_stub = super->pfd;

	//LOG_INFO("value of i: %d \n", i);
	//LOG_INFO("New block of current open file(W): %s \n", node->Inode_name);

	//if(node->fcontent_buf_curr == NULL && node->fcontent_buf_tail == NULL){
		//strncpy(curr_block->content_buf, buf, len);
		//int context = node->Inode_size;
//	LOG_INFO("new block of file \n");
	/*	for(int x=0; x<len; x++){
			if(buf[x]=='\0')
				curr_block->content_buf[x] = '.';		
			else
				curr_block->content_buf[x] = buf[x];
		}	
	}*/

	/*else{
		LOG_INFO("%dth block of new file \n", i);
		int context = node->Inode_size;
		for(int x=0; x<len; x++){
			if(buf[x]=='\0')
				curr_block->content_buf[context++] = '.';		
			else
				curr_block->content_buf[context++] = buf[x];
		}
	}*/


	//LOG_INFO("Copied data into file: %s \n", curr_block->content_buf);
	
	if(node->fcontent_buf_curr != NULL && node->fcontent_buf_tail != NULL){
		prev_block->block_next = curr_block->location;
	}

	curr_block->block_prev = node->fcontent_buf_curr;	
	curr_block->block_next = NULL;
	//LOG_INFO("upto here complete..(1)\n");
	//node->size_max;
	node->Inode_size=0;
	//node->parent;
	//node->child[20];
	if(node->fcontent_buf_curr == NULL && node->fcontent_buf_tail == NULL){
		node->fcontent_buf_head = curr_block->location;
	}
	//LOG_INFO("upto here complete..(2)\n");
	
	node->fcontent_buf_curr = curr_block->location;
	node->fcontent_buf_tail = curr_block->location;
	//LOG_INFO("upto here complete..(3)\n");	
	return (curr_block->location);
}


size_t fs_filewrite_TODO(size_t index, size_t part_addr, size_t root_addr, size_t block_start_addr, char *buf, size_t len){

	struct fs_Superblk *super;
	struct fs_Inode *node;
	struct FileBlock_list_node *curr_block, *prev_block;

	super = part_addr;
	node = super->pfd;	
	prev_block = node->fcontent_buf_curr;

	int i;
	for(i = 0; i< NUMBER_FILES; i++ ){
		if(super->free_fsblock_map[i] == 1){
			break;	
		}
	}
	

	super->free_fsblock_map[i] = 0;
	curr_block = block_start_addr + (sizeof(struct FileBlock_list_node) * (i));
	curr_block->location = block_start_addr + (sizeof(struct FileBlock_list_node) * (i));
	
	//node_stub = super->pfd;

	//LOG_INFO("value of i: %d \n", i);
	//LOG_INFO("Name of current open file(W): %s \n", node->Inode_name);

	//size_t 	location;		
	if(node->fcontent_buf_curr == NULL && node->fcontent_buf_tail == NULL){
		//strncpy(curr_block->content_buf, buf, len);
		//int context = node->Inode_size;
		//LOG_INFO("First block of new file \n");
		for(int x=0; x<len; x++){
			if(buf[x]=='\0')
				curr_block->content_buf[x] = '.';		
			else
				curr_block->content_buf[x] = buf[x];
		}	
	}

	else{
		//LOG_INFO("%dth block of new file \n", i);
		int context = node->Inode_size;
		for(int x=0; x<len; x++){
			if(buf[x]=='\0')
				curr_block->content_buf[context++] = '.';		
			else
				curr_block->content_buf[context++] = buf[x];
		}
	}
	//LOG_INFO("Copied data into file: %s \n", curr_block->content_buf);
	
	if(node->fcontent_buf_curr != NULL && node->fcontent_buf_tail != NULL){
		prev_block->block_next = curr_block->location;
	}

	curr_block->block_prev = node->fcontent_buf_curr;	
	curr_block->block_next = NULL;

	node->size_max;
	node->Inode_size;
	//node->parent;
	//node->child[20];
	if(node->fcontent_buf_curr == NULL && node->fcontent_buf_tail == NULL){
		node->fcontent_buf_head = curr_block->location;
	}
	
	node->fcontent_buf_curr = curr_block->location;
	node->fcontent_buf_tail = curr_block->location;
	return 0;
}


struct fs_File* fs_fileread(size_t index, size_t part_addr, size_t root_addr){

	//change......

	struct fs_Superblk *super;
	struct fs_Inode *node;
	//struct fs_File*

	super = part_addr;
	node = super->pfd;	

	//LOG_INFO("Name of current open file(R): %s \n", node->Inode_name);
	memset(&curr_file, 0x00, sizeof(struct fs_File));

	strcpy(curr_file.file_name, node->Inode_name);
	strcpy(curr_file.file_path, node->Inode_path);
	curr_file.location = super->pfd;
	curr_file.size_max = BLOCK_SIZE_MAX;
	curr_file.file_size = 0;
	curr_file.parent = super->pwd;
	curr_file.content_buf_head = node->fcontent_buf_head;
	curr_file.content_buf_tail = node->fcontent_buf_tail;
	curr_file.content_buf_curr = node->fcontent_buf_curr;
	//LOG_INFO("return to syscall level \n");
	
	return (&curr_file);


}


void to_delete(size_t part_addr, size_t addr_ptr){

	struct fs_Superblk *super;
	struct fs_Inode *node, *node_stub;
	super = part_addr;
	node = addr_ptr;	

	for(int i =0 ; i<NUMBER_INODES; i++){
		if(node->child[i] != NULL){
			node_stub = node->child[i];
			if(strcmp(node_stub->Inode_type,"D") == 0){	
				to_delete(part_addr, node->child[i]);
				super->free_inode_map[node_stub->Inode_index] = 1;				
				memset(node->child[i], NULL, sizeof(struct fs_Inode));				
				node->child[i] = NULL;		
				for(int shift = i; shift < NUMBER_INODES; shift ++){
					node->child[shift] = node->child[shift+1];
				}	

			}

			else if(strcmp(node_stub->Inode_type,"F") == 0){
				super->free_fsblock_map[node_stub->Inode_index] = 1;
				//LOG_INFO("Before deletion: %s \n", node_stub->Inode_name);
				struct FileBlock_list_node *block_ptr;
				block_ptr= node_stub->fcontent_buf_head;
				while(block_ptr != NULL){
					size_t ptr_stub = block_ptr;
					block_ptr = block_ptr-> block_next;
					memset(ptr_stub, NULL, sizeof(struct FileBlock_list_node));	
				}
				memset(node->child[i], NULL, sizeof(struct fs_Inode));
				//LOG_INFO("After deletion: %s \n", node_stub->Inode_name);
				node->child[i] = NULL;
				for(int shift = i; shift < NUMBER_INODES; shift ++){
					node->child[shift] = node->child[shift+1];
				}

			}	

		}
	}	
}



size_t fs_removeInode(size_t part_addr, size_t root_addr, char *name){

	struct fs_Superblk *super;
	struct fs_Inode *node, *node_stub;

	super = part_addr;
	node = super->pwd;
	int i,j;

	for(i =0 ; i<NUMBER_INODES; i++){
		if(node->child[i] != NULL){
			node_stub = node->child[i];
			if( node->child[i] != NULL && strcmp(node_stub->Inode_name,name) == 0){
				//LOG_INFO("Found Node for deletion: %s \n", node_stub->Inode_name);

				if(strcmp(node_stub->Inode_type,"D") == 0){	
					to_delete(super, node->child[i]);			 
					super->free_inode_map[node_stub->Inode_index] = 1;
					//LOG_INFO("Before deletion: %s \n", node_stub->Inode_name);
					memset(node->child[i], NULL, sizeof(struct fs_Inode));
					//LOG_INFO("After deletion: %s \n", node_stub->Inode_name);
					node->child[i] = NULL;
					for(int shift = i; shift < NUMBER_INODES; shift ++){
						node->child[shift] = node->child[shift+1];
					}	
						
				}
				else if(strcmp(node_stub->Inode_type,"F") == 0){
					super->free_fsblock_map[node_stub->Inode_index] = 1;
					//LOG_INFO("Before deletion: %s \n", node_stub->Inode_name);
					struct FileBlock_list_node *block_ptr;
					block_ptr= node_stub->fcontent_buf_head;
					while(block_ptr != NULL){
						size_t ptr_stub = block_ptr;
						block_ptr = block_ptr-> block_next;
						memset(ptr_stub, NULL, sizeof(struct FileBlock_list_node));	
					}
					memset(node->child[i], NULL, sizeof(struct fs_Inode));
					//LOG_INFO("After deletion: %s \n", node_stub->Inode_name);
					node->child[i] = NULL;
					for(int shift = i; shift < NUMBER_INODES; shift ++){
						node->child[shift] = node->child[shift+1];
					}

				}	

				break;
			}
		}
	}

	


	return 0;

}


