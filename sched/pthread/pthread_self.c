
#include <pthread.h>

pthread_t pthread_self(void){
    return (pthread_t)getpid();
}
