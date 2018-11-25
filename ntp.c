#include "dpi.h"

int detec_ntp(struct protocol_info *pi)
{
    if (pi->udphdr->source==htons(123)||pi->udphdr->dest==htons(123))
    {
        detec_save(pi,PRO_NTP);
        return 1;
    }

    if (detec_cmp(pi,PRO_NTP)==1)
    {
        return 1;
    }

    return 0;
}
