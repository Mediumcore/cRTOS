
#include <sys/mman.h>

int mlockall(int flags) {
    return 0;
}

int munlock(FAR const void *addr, size_t len) {
    return 0;
}

int munlockall(void) {
    return 0;
}
