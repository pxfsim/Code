#ifndef __LOG_H__
#define __LOG_H__

#include "dpi.h"

#define LOG_SWITCH 1


#define log_err(...) printf(__VA_ARGS__)

#define log_info(...) printf(__VA_ARGS__)

#define log_dbg(...) do {    \
    printf("FILE:%s FUNCTION:%s LINE:%d \t",__FILE__,__func__,__LINE__); \
    printf(__VA_ARGS__);    \
}while(0)

#endif //__LOG_H__
