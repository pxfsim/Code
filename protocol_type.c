#include "dpi.h"

//保存协议对应的四元组数据
static four_tulpes_t four_info[PRO_TYPES_MAX];


int detec_save(struct protocol_info *pi,int types)
{

    four_info[types].sip=pi->iphdr->saddr;
    four_info[types].dip=pi->iphdr->daddr;

    if (pi->iphdr->protocol==IPPROTO_TCP)
    {
        four_info[types].sport=pi->tcphdr->source;
        four_info[types].dport=pi->tcphdr->dest;
    }

    if (pi->iphdr->protocol==IPPROTO_UDP)
    {
        four_info[types].sport=pi->udphdr->source;
        four_info[types].dport=pi->udphdr->dest;
    }

    return 1;
}

int detec_cmp(struct protocol_info *pi,int types)
{
    if (pi->iphdr->protocol==IPPROTO_TCP)
    {
        if (pi->iphdr->saddr==four_info[types].sip
            && pi->iphdr->daddr==four_info[types].dip
            && pi->tcphdr->source==four_info[types].sport 
            && pi->tcphdr->dest==four_info[types].dport
           )
        {
            return 1;
        }

        if (pi->iphdr->saddr==four_info[types].dip
            && pi->iphdr->daddr==four_info[types].sip
            && pi->tcphdr->source==four_info[types].dport 
            && pi->tcphdr->dest==four_info[types].sport
           )
        {
            return 1;
        }
    }

    if (pi->iphdr->protocol==IPPROTO_UDP)
    {
        if (pi->iphdr->saddr==four_info[types].sip
            && pi->iphdr->daddr==four_info[types].dip
            && (pi->udphdr->source==four_info[types].sport 
            || pi->udphdr->dest==four_info[types].dport
            )
            )
        {
            return 1;
        }

        if (pi->iphdr->saddr==four_info[types].dip
            && pi->iphdr->daddr==four_info[types].sip
            && (pi->udphdr->source==four_info[types].sport 
            || pi->udphdr->dest==four_info[types].dport
            )
            )
        {
            return 1;
        }
    }

    return 0;
}









