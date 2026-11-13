#include <import/eb32tree.h>
#include <haproxy/api.h>
#include <haproxy/backend.h>
#include <haproxy/queue.h>
#include <haproxy/server-t.h>
#include <haproxy/global.h>
#include <haproxy/lb_n2sl.h>
#include <collector/shared_types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <haproxy/n2sl_table.h>
#include <haproxy/tools.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

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

ServerSlot* shm_servers = NULL;

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
	if (shm_servers){
		atomic_store(&shm_servers[srv->n2sl_shm_idx].status, srv_willbe_usable(srv) ? SERVER_STATUS_UP : SERVER_STATUS_DOWN);
	}
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
	if (shm_servers){
		atomic_store(&shm_servers[srv->n2sl_shm_idx].status, srv_willbe_usable(srv) ? SERVER_STATUS_UP : SERVER_STATUS_DOWN);
	}
	srv_lb_commit_status(srv);
}

void n2sl_init_server_tree(struct proxy *p)
{
	fprintf(stderr, "[N2SL] init_server_tree: proxy=%s\n", p->id);
	struct server *srv;
	struct eb_root init_head = EB_ROOT;


	//ToDo: backend count 관리하는 전역변수 생성 및 snprintf 0 대신 넣기
    char shm_name[64];
    snprintf(shm_name, sizeof(shm_name), "/n2sl_backend_%d", 0);

    shm_servers = NULL;
    int fd = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
    if (fd == -1) {
        fprintf(stderr, "[N2SL] shm_open 실패: %s\n", shm_name);
    } else {
        if (ftruncate(fd, sizeof(ServerSlot) * MAX_SERVERS) == 0) {
            void *m = mmap(NULL, sizeof(ServerSlot) * MAX_SERVERS, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (m != MAP_FAILED)
                shm_servers = m;
        }
        close(fd);
    }
									
    // shm_servers, fd를 이 backend(p)와 연결해서 보관해야 함 — p->lbprm.n2sl 쪽에 필드 추가 필요해 보임
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
	p->lbprm.wdiv = BE_WEIGHT_SCALE;
	for (srv = p->srv; srv; srv = srv->next) {
		srv->next_eweight = (srv->uweight * p->lbprm.wdiv + p->lbprm.wmult - 1) / p->lbprm.wmult;
		srv_lb_commit_status(srv);
	}
	recount_servers(p);
	/* This function simply updates the backend's tot_weight and tot_used values after servers weights have been updated.*/
	update_backend_weight(p);

	//n2sl active / backup ToDo: act/bck 구조체에 n2sl 등록해야힘
	p->lbprm.n2sl.act = init_head;
	p->lbprm.n2sl.bck = init_head;

	int slot_idx = 0;
	/* queue active and backup servers in two distinct groups */
	for (srv = p->srv; srv; srv = srv->next) {
		if (slot_idx >= MAX_SERVERS) {
			fprintf(stderr, "[N2SL] 서버 개수가 MAX_SERVERS(%d)를 초과함, 나머지는 shm에 못 씀\n", MAX_SERVERS);
			break;
		}
		if (shm_servers) {
			addr_to_str(&srv->addr, shm_servers[slot_idx].ip, sizeof(shm_servers[slot_idx].ip));
			shm_servers[slot_idx].port = srv->svc_port;
			atomic_store(&shm_servers[slot_idx].status, SERVER_STATUS_UP);
		}
		/* 나중에 up/down 콜백에서 이 서버가 몇 번 슬롯이었는지 찾을 수 있게 저장 */
		srv->n2sl_shm_idx = slot_idx;
		slot_idx++;

		if (!srv_currently_usable(srv)){
			continue;
		}
		srv->lb_tree = (srv->flags & SRV_F_BACKUP) ? &p->lbprm.fas.bck : &p->lbprm.fas.act;
		n2sl_queue_srv(srv);
	}

}

/* ===== 모델 표로 서버 고르기 ===== */
struct n2sl_shm {
        const n2sl_table_t *tbl;
        n2sl_assign_t      *asg;
};

static struct n2sl_shm *n2sl_shm_p;   /* 한 번 열면 계속 사용 */
static unsigned int n2sl_rr;          /* round robin 순번 */

static int64_t n2sl_now_ms(void)
{
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Collector가 만든 공유메모리를 연다. 아직 없으면 NULL을 돌려주고, 다음 요청 때 다시 시도한다 */
static struct n2sl_shm *n2sl_get_shm(void)
{
        struct n2sl_shm *s = __atomic_load_n(&n2sl_shm_p, __ATOMIC_ACQUIRE);
        if (s)
                return s;

        struct stat st1, st2;
        int fd1 = shm_open("/n2sl_table", O_RDONLY, 0);
        if (fd1 < 0)
                return NULL;
        int fd2 = shm_open("/n2sl_assign", O_RDWR, 0);
        if (fd2 < 0) {
                close(fd1);
                return NULL;
        }
        /* Collector가 크기를 정하기 전이면 mmap하지 않는다 (작은 파일을 매핑하면 SIGBUS) */
        if (fstat(fd1, &st1) || fstat(fd2, &st2) ||
            st1.st_size < (off_t)sizeof(n2sl_table_t) || st2.st_size < (off_t)sizeof(n2sl_assign_t)) {
                close(fd1); close(fd2);
                return NULL;
        }
        void *t = mmap(NULL, sizeof(n2sl_table_t), PROT_READ, MAP_SHARED, fd1, 0);
        void *a = mmap(NULL, sizeof(n2sl_assign_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
        close(fd1); close(fd2);
        s = malloc(sizeof(*s));
        if (t == MAP_FAILED || a == MAP_FAILED || !s) {
                if (t != MAP_FAILED) munmap(t, sizeof(n2sl_table_t));
                if (a != MAP_FAILED) munmap(a, sizeof(n2sl_assign_t));
                free(s);
                return NULL;
        }
        s->tbl = t;
        s->asg = a;

        /* 스레드 2개가 동시에 열었으면 먼저 등록한 쪽을 쓰고 내 것은 버린다 */
        struct n2sl_shm *expect = NULL;
        if (!__atomic_compare_exchange_n(&n2sl_shm_p, &expect, s, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                munmap((void *)s->tbl, sizeof(n2sl_table_t));
                munmap(s->asg, sizeof(n2sl_assign_t));
                free(s);
                return expect;
        }
        return s;
}

/* 모델 표로 고른다. 판단할 수 없으면 NULL을 돌려준다 */
static struct server *n2sl_model_pick(struct proxy *p)
{
        struct n2sl_shm *s = n2sl_get_shm();
        if (!s)
                return NULL;                                  /* 표 없음 */

        const n2sl_table_t *t = s->tbl;
        struct server *map[N2SL_MAX_SRV] = { NULL };
        unsigned char alive[N2SL_MAX_SRV] = { 0 };
        uint32_t n = t->n_srv < N2SL_MAX_SRV ? t->n_srv : N2SL_MAX_SRV;
        char ip[64];
        struct server *srv;

        for (srv = p->srv; srv; srv = srv->next) {
                if (!srv_currently_usable(srv) || (srv->flags & SRV_F_BACKUP))
                        continue;
                if (addr_to_str(&srv->addr, ip, sizeof(ip)) < 0)
                        return NULL;
                int found = -1;
                for (uint32_t i = 0; i < n; i++) {
                        if (strncmp(t->srv[i].key, ip, N2SL_KEY_LEN) == 0) {
                                found = (int)i;
                                break;
                        }
                }
                if (found < 0)
                        return NULL;                              /* 표에 없는 서버가 있음 */
                map[found] = srv;
                alive[found] = 1;
        }

        int k = n2sl_pick(t, s->asg, alive, n2sl_now_ms(), 3000);   /* 3초보다 오래된 표면 -1 */
        return k >= 0 ? map[k] : NULL;
}

/* 판단할 수 없을 때 쓰는 round robin */
static struct server *n2sl_rr_pick(struct proxy *p)
{
        struct server *list[N2SL_MAX_SRV];
        struct server *srv;
        int n = 0;

        for (srv = p->srv; srv && n < N2SL_MAX_SRV; srv = srv->next)
                if (srv_currently_usable(srv) && !(srv->flags & SRV_F_BACKUP))
                        list[n++] = srv;
        if (!n)
                return NULL;
        return list[HA_ATOMIC_FETCH_ADD(&n2sl_rr, 1) % n];
}

struct server *n2sl_get_next_server(struct proxy *p)
{
	struct server *srv = NULL;

	HA_RWLOCK_RDLOCK(LBPRM_LOCK, &p->lbprm.lock);

	//active server 중에서 선택	
	if (p->srv_act) {
        srv = n2sl_model_pick(p);
        if (!srv)
            srv = n2sl_rr_pick(p);
        goto out;
    }

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
	return srv;
}

