#include "dpi.h"

//协议标识 
static char *protocol_string[PRO_TYPES_MAX]={PRO_STRINGS};

//初始化
protocol_info_t * protocol_info_init()
{
    protocol_info_t *p=(protocol_info_t *)malloc(sizeof(protocol_info_t));
    if (p==NULL)
    {
        return NULL;
    }

    memset(p,0,sizeof(protocol_info_t));

    p->detec_func=(struct detec_info *)malloc(sizeof(struct detec_info)*PRO_TYPES_MAX);

//SSH协议识别
#ifdef PRO_SSH
    p->detec_func[PRO_SSH].flag=0;
    p->detec_func[PRO_SSH].func=detec_ssh;
#endif

//TFPT协议识别
#ifdef PRO_TFPT
    p->detec_func[PRO_TFPT].flag=1;
    p->detec_func[PRO_TFPT].func=detec_tfpt;
#endif

//NTP协议识别
#ifdef PRO_NTP
    p->detec_func[PRO_NTP].flag=1;
    p->detec_func[PRO_NTP].func=detec_ntp;
#endif

    return p;

}

//输出
int protocol_info_out(protocol_info_t *pi)
{

    log_info("packet count:%d\n",pi->ptk_count);    

    log_info("ip packet count:%d\n",pi->ip_count);    

    log_info("ipv4 packet count:%d\n",pi->ipv4_count);    

    int i=0;
    for (i=0;i<PRO_TYPES_MAX;i++)
    {
        log_info("%s:%d\n",protocol_string[i],pi->protocol_types[i]);
    }
    return 0;
}

//释放
void protocol_info_free(protocol_info_t * pi)
{
    free(pi->detec_func);
    free(pi);
}
