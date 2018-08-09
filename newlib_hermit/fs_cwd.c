#include "config.h"
#include <_ansi.h>
#include <_syslist.h>
#include "syscall.h"

ssize_t
_DEFUN (fs_cwd, (buf), char* buf)
{

/* call HermitCore implementation */
return sys_fs_cwd(buf);
}
