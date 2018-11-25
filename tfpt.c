#include "dpi.h"


int detec_tfpt(struct protocol_info *pi)
{
    char *p=(char *)((char *)pi->udphdr+sizeof(struct udphdr));

    if (*(unsigned short *)p==htons(1) ||
        *(unsigned short *)p==htons(2))
    {
        p=p+2+strlen(p+2)+1;
        if (strcmp(p,"netascii")==0 ||
            strcmp(p,"octet")==0)
        {
            detec_save(pi,PRO_TFPT); 
            return 1;
        }
    }

    if (detec_cmp(pi,PRO_TFPT)==1)
    {
        return 1;
    }

    return 0;
}
