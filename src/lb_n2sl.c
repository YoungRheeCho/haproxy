#include <import/eb32tree.h>
#include <haproxy/api.h>
#include <haproxy/backend.h>
#include <haproxy/queue.h>
#include <haproxy/server-t.h>
#include <haproxy/global.h>
#include <haproxy/lb_n2sl.h>

/*
1. init function
2. server status up
3. server status down
-----
4. next server: next server selection algorithm will be written in this func
*/
static inline void n2sl_remove_from_tree(struct server *s);
static inline void n2sl_dequeue_srv(struct server *s);
static inline void n2sl_queue_srv(struct server *s);
static void n2sl_set_server_status_down(struct server *srv);
static void n2sl_set_server_status_up(struct server *srv);

//server는 lb_tree를 통해서 act/back을 판단함
static inline void n2sl_remove_from_tree(struct server *s)
{
	s->lb_tree = NULL;
}

//tree에서 server 객체를 삭제
static inline void n2sl_dequeue_srv(struct server *s)
{
	eb32_delete(&s->lb_node);
}

static inline void n2sl_queue_srv(struct server *s)
{
	s->lb_node.key = s->puid;
	eb32_insert(s->lb_tree, &s->lb_node);
}
/*
srv_lb_status_changed 체크 → srv_willbe_usable면 스킵 → WRLOCK → srv_currently_usable면 스킵 → (ToDo)실제 제거  → unlock → srv_lb_commit_status
*/
//ToDo: 서버가 죽었을 때, look up table(alive server list)를 공유해야함
static void n2sl_set_server_status_down(struct server *srv)
{
	struct proxy *p = srv->proxy;

	if (!srv_lb_status_changed(srv))
		return;

    /*
    health check를 통해서 서버의 다음 상태와 현재 상태를 나타내는 field가 server 구조체에 존재함
    enum srv_state next_state, cur_state;
    해당 상태들을 확인하여 다음 상태가 usable인지, 그리고 현재 상태가 usable인지를 모두 검사 후, cur state는 살았지만 next state가 죽었다고 판단하면 status down 로직을 통해 data structure를 수정함
    */

	if (srv_willbe_usable(srv))
		goto out_update_state;

	HA_RWLOCK_WRLOCK(LBPRM_LOCK, &p->lbprm.lock);

	if (!srv_currently_usable(srv))
	/* server was already down */
	goto out_update_backend;

	if (srv->flags & SRV_F_BACKUP) {
		p->lbprm.tot_wbck -= srv->cur_eweight;
		p->srv_bck--;
		
		if (srv == p->lbprm.fbck) {
			/* we lost the first backup server in a single-backup
			* configuration, we must search another one.
			*/
		struct server *srv2 = p->lbprm.fbck;
		do {
			srv2 = srv2->next;
		} while (srv2 &&
			!((srv2->flags & SRV_F_BACKUP) &&
			srv_willbe_usable(srv2)));
			p->lbprm.fbck = srv2;
		}
	} else {
		p->lbprm.tot_wact -= srv->cur_eweight;
		p->srv_act--;
	}
		
	/* TODO: LookUp Table 업데이트 */
	n2sl_dequeue_srv(srv);
	n2sl_remove_from_tree(srv);


out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
	HA_RWLOCK_WRUNLOCK(LBPRM_LOCK, &p->lbprm.lock);

 out_update_state:
	srv_lb_commit_status(srv);
}

//ToDo: 서버가 살아났을 때, look up table(alive server list)를 공유해야함
static void n2sl_set_server_status_up(struct server *srv){
	struct proxy *p = srv->proxy;

	if (!srv_lb_status_changed(srv))
		return;

	if (!srv_willbe_usable(srv))
		goto out_update_state;

	HA_RWLOCK_WRLOCK(LBPRM_LOCK, &p->lbprm.lock);

	if (srv_currently_usable(srv))
		/* server was already up */
		goto out_update_backend;


	/* TODO: 자료 구조 업데이트 되어야 함. up된 서버를 자료구조에 추가 */
	if (srv->flags & SRV_F_BACKUP) {
		srv->lb_tree = &p->lbprm.fas.bck;
		p->lbprm.tot_wbck += srv->next_eweight;
		p->srv_bck++;

		if (!(p->options & PR_O_USE_ALL_BK)) {
			if (!p->lbprm.fbck) {
				/* there was no backup server anymore */
				p->lbprm.fbck = srv;
			} else {
				/* we may have restored a backup server prior to fbck,
				 * in which case it should replace it.
				 */
				struct server *srv2 = srv;
				do {
					srv2 = srv2->next;
				} while (srv2 && (srv2 != p->lbprm.fbck));
				if (srv2)
					p->lbprm.fbck = srv;
			}
		}
	} else {
		srv->lb_tree = &p->lbprm.fas.act;
		p->lbprm.tot_wact += srv->next_eweight;
		p->srv_act++;
	}

	n2sl_queue_srv(srv);
 out_update_backend:
	/* check/update tot_used, tot_weight */
	update_backend_weight(p);
	HA_RWLOCK_WRUNLOCK(LBPRM_LOCK, &p->lbprm.lock);

 out_update_state:
	srv_lb_commit_status(srv);
}

void n2sl_init_server_tree(struct proxy *p)
{
	fprintf(stderr, "[N2SL] init_server_tree: proxy=%s\n", p->id);
	struct server *srv;
	struct eb_root init_head = EB_ROOT;
	
	/*load balancer interface 목록*/
	/* Call backs for some actions. Any of them may be NULL (thus should be ignored).
	 * Those marked "srvlock" will need to be called with the server lock held.
	 * The other ones might take it themselves if needed.
	 */
	//p->lbprm.update_server_eweight = ;		/* to be called after eweight change // srvlock */
	//p->lbprm.server_take_conn = ; 			/* to be called when connection is assigned */
	//p->lbprm.server_drop_conn = ;				/* to be called when connection is dropped */
	//p->lbprm.server_requeue = ;				/* function used to place the server where it must be */
	//p->lbprm.proxy_deinit = ;					/* to be called when we're destroying the proxy */
	//p->lbprm.server_deinit = ;				/* to be called when we're destroying the server */
	p->lbprm.set_server_status_up   = n2sl_set_server_status_up; /* to be called after status changes to UP // srvlock */
	p->lbprm.set_server_status_down = n2sl_set_server_status_down; /* to be called after status changes to DOWN // srvlock */
	

	//This function recounts the number of usable active and backup servers for proxy <p>
	recount_servers(p);
	/* This function simply updates the backend's tot_weight and tot_used values after servers weights have been updated.*/
	update_backend_weight(p);

	//n2sl active / backup ToDo: act/bck 구조체에 n2sl 등록해야힘
	p->lbprm.n2sl.act = init_head;
	p->lbprm.n2sl.bck = init_head;

	/* queue active and backup servers in two distinct groups */
	for (srv = p->srv; srv; srv = srv->next) {
		if (!srv_currently_usable(srv))
			continue;
		srv->lb_tree = (srv->flags & SRV_F_BACKUP) ? &p->lbprm.fas.bck : &p->lbprm.fas.act;
		n2sl_queue_srv(srv);
	}
}

struct server *n2sl_get_next_server(struct proxy *p)
{
	fprintf(stderr, "[N2SL] get_next_server: called\n");
	struct server *srv = NULL;
	fprintf(stderr, "[N2SL] get_next_server called\n");

	HA_RWLOCK_RDLOCK(LBPRM_LOCK, &p->lbprm.lock);

	//active server 중에서 선택	
	if (p->srv_act){}

	//active server 중에서 alive가 없을 경우 first backup server를 선택
	else if (p->lbprm.fbck) {
		srv = p->lbprm.fbck;
		goto out;
	}

	/*
	* first backup server가 없고 중에서 선택 backup server만 있을 경우 back up server에서 선택
	* 사실 상 거의 동작 x -> race condition으로 first back up server가 선정되기 전에 next server get 함수 동작하는 경우에 해당 분기 실행
	*/
	else if (p->srv_bck){}
	
	else {
		srv = NULL;
		goto out;
	}

  out:
	HA_RWLOCK_RDUNLOCK(LBPRM_LOCK, &p->lbprm.lock);
	fprintf(stderr, "[N2SL] get_next_server: returning %s\n", srv ? srv->id : "NULL");
	return srv;
}

