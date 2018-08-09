#include "config.h"
#include <_ansi.h>
#include <_syslist.h>
#include "syscall.h"

ssize_t
_DEFUN (group_fileread, (fd, buf, len), size_t *fd _AND char* buf _AND size_t len)
{

/* call HermitCore implementation */
return sys_group_fileread(fd, buf, len);
}
