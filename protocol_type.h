#ifndef __PROTOCOL_TYPE_H__
#define __PROTOCOL_TYPE_H__

#include "dpi.h"

#define PRO_UNKNOWN 0
#define PRO_SSH 1
#define PRO_TFPT 2
#define PRO_NTP 3

#define PRO_LAST PRO_NTP
#define PRO_TYPES_MAX (PRO_LAST+1)

#define PRO_STRINGS "unknown","ssh","tfpt","ntp"


struct protocol_info;

//保存四元组
extern int detec_save(struct protocol_info *pi,int types);

//四元组对比
extern int detec_cmp(struct protocol_info *pi,int types);

//四元组结构体
typedef struct four_tulpes
{
    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
}four_tulpes_t;



#endif // __PROTOCOL_TYPE_H__
