#include "config.h"
#include <_ansi.h>
#include <_syslist.h>
#include "syscall.h"

ssize_t 
_DEFUN (fs_fclose, (name), char *name)
{
return sys_fs_fclose(name);
}
