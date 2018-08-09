#include "config.h"
#include <_ansi.h>
#include <_syslist.h>
#include "syscall.h"

ssize_t 
_DEFUN (fs_fopen, (name, mode), char *name _AND char* mode)
{
return sys_fs_fopen(name,mode);
}
