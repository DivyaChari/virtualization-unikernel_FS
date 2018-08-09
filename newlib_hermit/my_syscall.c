#include "config.h"
#include <_ansi.h>
#include <_syslist.h>
#include "syscall.h"

int
_DEFUN (my_syscall, (x),
int x)
{
/* call the kernel implementation */
return sys_my_syscall(x);
}
