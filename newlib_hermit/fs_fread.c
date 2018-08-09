#include "config.h"
#include <_ansi.h>
#include <_syslist.h>
#include "syscall.h"

ssize_t
_DEFUN (fs_fread, (index,buf,mode,len), size_t index _AND char *buf _AND char *mode _AND size_t len)
{ 

/* call HermitCore implementation */
return sys_fs_fread(index,buf,mode,len);
}
