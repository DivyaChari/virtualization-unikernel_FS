#include "config.h"
#include <_ansi.h>
#include <_syslist.h>
#include "syscall.h"

ssize_t
_DEFUN (group_filewrite, (fd, buf, len), size_t *fd _AND char* buf _AND size_t len)
{
//int ret;
/* call HermitCore implementation */
return sys_group_filewrite(fd, buf, len);

}
