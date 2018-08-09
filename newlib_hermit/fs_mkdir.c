#include "config.h"
#include <_ansi.h>
#include <_syslist.h>
#include "syscall.h"

ssize_t 
_DEFUN (fs_mkdir, (name), char *name)
{
return sys_fs_mkdir(name);
}


