#include "sim-assert.h"
#include "sim-types.h"

#include <sys/sysctl.h>
int nsc_sysctl(const char *sysctl_name, void *oldval, size_t *oldlenp,
    void *newval, size_t newlen)
{
    int retval = 0;
    int error = kernel_sysctlbyname(curthread, sysctl_name, oldval, oldlenp,
            newval, newlen, &retval);
    return error;
}

