#include "dpi.h"

int detec_ssh(struct protocol_info *pi)
{

    char *data=(char *)pi->tcphdr+pi->tcphdr->doff*4;


    if (ntohs(pi->iphdr->tot_len)-pi->iphdr->ihl*4-pi->tcphdr->doff*4<5)
    {
        return 0;
    }

    if (strncmp(data,"SSH-",4)==0)
    {
        detec_save(pi,PRO_SSH);
        return 1;
    }

    if (detec_cmp(pi,PRO_SSH))
        return 1;
    return 0;
}
