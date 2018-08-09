#include "config.h"
#include <_ansi.h>
#include <_syslist.h>
#include "syscall.h"

size_t 
_DEFUN (fs_frm, (name), char *name)
{
return sys_fs_frm(name);
}
