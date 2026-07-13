#ifndef _HAPROXY_LB_N2SL_T_H
#define _HAPROXY_LB_N2SL_T_H 

#include <import/ebtree-t.h>

struct lb_n2sl {
	struct eb_root act;	/* weighted least conns on the active servers */
	struct eb_root bck;	/* weighted least conns on the backup servers */
};

#endif