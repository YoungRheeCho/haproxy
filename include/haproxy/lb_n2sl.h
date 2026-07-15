#ifndef _HAPROXY_LB_N2SL_H
#define _HAPROXY_LB_N2SL_H 

#include <haproxy/api.h>
#include <haproxy/proxy-t.h>
#include <haproxy/server-t.h>

void n2sl_init_server_tree(struct proxy *p);
struct server *n2sl_get_next_server(struct proxy *p);

#endif