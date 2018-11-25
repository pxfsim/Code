#ifndef __PROTOCOLINFO_H__
#define __PROTOCOLINFO_H__

#include "dpi.h"

/*
 * 用于记录分析后的信息
 */


struct detec_info;

typedef struct protocol_info
{
    int ptk_count;  //统计PACKET总数
    int ip_count;   //统计IP PACKET 总数
    int ipv4_count; //统计IPV4 PACKET 总数


    struct ethhdr * ethhdr;     //以太网帧
    struct iphdr * iphdr;       //IP
    struct tcphdr * tcphdr;     //TCP
    struct udphdr * udphdr;     //UDP

    int protocol_types[PRO_TYPES_MAX];
    struct detec_info *detec_func; 
    
}protocol_info_t;

typedef int (*pro_detec)(protocol_info_t * pi);

struct detec_info
{
    int flag;       //TCP OR UDP
    pro_detec func;
};

extern int detec_ssh(struct protocol_info *pi);

//初始化
protocol_info_t * protocol_info_init();

//输出
int  protocol_info_out(protocol_info_t *pi);

//释放资源
void protocol_info_free(protocol_info_t *pi);

#endif //__PTRINFO_H__
