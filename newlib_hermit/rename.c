#include "config.h"
#include <reent.h>
#include <_ansi.h>
#include <_syslist.h>
#include <errno.h>
#include "syscall.h"
#include "warning.h"

int
_DEFUN (rename, (oldpath, newpath),
const char *oldpath _AND
const char *newpath)
{
return _rename_r(_REENT, oldpath, newpath);
}

int
_DEFUN (_rename_r, (p, oldpath, newpath), struct _reent *p _AND const char *oldpath _AND const char *newpath)
{
int ret;
/* call HermitCore implementation */
ret = sys_rename(oldpath, newpath);
if (ret < 0) {
p->_errno = -ret;
ret = -1;
}

return ret;
}





