/* n2sl LB 공유메모리 형식 (모델 프로세스 ↔ HAProxy n2sl 알고리즘)
 *
 * 파일 두 개 (모델 프로세스가 만들고 크기를 정한다):
 *   /dev/shm/n2sl_table   모델 → HAProxy. 1초마다 새 표. seqlock으로 보호 (쓰는 쪽은 모델 하나뿐)
 *   /dev/shm/n2sl_assign  HAProxy → 모델. 서버별 누적 배정 수. HAProxy가 원자적으로 +1
 *
 * 배정 규칙 (n2sl_pick):
 *   이번 표 이후 서버 i에 보낸 인원 used_i = assigned_i − base_assigned_i
 *   1) 자리가 남은 서버(used_i < seats_i)가 있으면 그중에서, 없으면 전체에서
 *   2) 다음 1명을 받은 뒤의 비용 cost_i[used_i + 1]이 가장 작은 서버 (증가분이 아니라 비용 자체를 비교)
 *   3) 같으면 남은 자리(seats_i − used_i)가 많은 서버, 그래도 같으면 앞 번호
 *   표가 없거나 stale_ms보다 오래됐으면 -1 → 호출 쪽에서 기본 알고리즘(예: leastconn)으로
 *
 * 모델 프로세스의 lb_shm.py(ctypes)와 크기가 같아야 한다: 아래 _Static_assert와 lb_shm.py의 출력 비교.
 */
#ifndef N2SL_TABLE_H
#define N2SL_TABLE_H

#include <stdint.h>
#include <math.h>

#define N2SL_MAGIC    0x4E32534Cu   /* 'N2SL' */
#define N2SL_VERSION  1u
#define N2SL_MAX_SRV  64
#define N2SL_KMAX     100
#define N2SL_KEY_LEN  48

typedef struct {
	char     key[N2SL_KEY_LEN];      /* HAProxy backend의 server 이름. 모델 설정의 key와 같아야 함 */
	int32_t  seats;                  /* 이번 표에서 더 받을 수 있는 인원 (경고 확률 기준 + 용량 규칙) */
	uint32_t base_assigned;          /* 표를 만들 때 읽은 assigned[i] */
	float    p_warn0;                /* 지금 상태의 경고 확률 (모니터링용) */
	float    p_crit0;                /* 지금 상태의 위험 확률 (모니터링용) */
	float    cost[N2SL_KMAX + 2];    /* k명 더 받았을 때 비용, k = 0..KMAX+1 */
} n2sl_srv_t;

typedef struct {
	uint32_t magic;
	uint32_t version;
	uint32_t seq;                    /* 홀수 = 쓰는 중 */
	uint32_t n_srv;
	uint64_t epoch;                  /* 표 번호 (1초마다 +1) */
	int64_t  built_ms;               /* 표를 만든 시각 (epoch ms) */
	n2sl_srv_t srv[N2SL_MAX_SRV];
} n2sl_table_t;

typedef struct {
	uint32_t magic;
	uint32_t version;
	uint32_t n_srv;
	uint32_t _pad;
	uint32_t assigned[N2SL_MAX_SRV]; /* 누적 배정 수. 인덱스는 n2sl_table_t.srv와 같음 */
} n2sl_assign_t;

_Static_assert(sizeof(n2sl_srv_t) == 472, "n2sl_srv_t size");
_Static_assert(sizeof(n2sl_table_t) == 32 + 472 * N2SL_MAX_SRV, "n2sl_table_t size");
_Static_assert(sizeof(n2sl_assign_t) == 16 + 4 * N2SL_MAX_SRV, "n2sl_assign_t size");

/* alive[i]: HAProxy가 아는 서버 i의 상태 (UP이면 1). 서버 이름 → i 매핑은 key로 한 번 만들어 두고 재사용.
 * 반환: 고른 인덱스 (assigned[i]를 +1 한 뒤), 실패하면 -1 */
static inline int n2sl_pick(const n2sl_table_t *t, n2sl_assign_t *a, const unsigned char *alive,
                            int64_t now_ms, int64_t stale_ms)
{
	for (int tries = 0; tries < 8; tries++) {
		uint32_t s1 = __atomic_load_n(&t->seq, __ATOMIC_ACQUIRE);
		if (s1 & 1u)
			continue;
		if (t->magic != N2SL_MAGIC || t->version != N2SL_VERSION || now_ms - t->built_ms > stale_ms)
			return -1;
		uint32_t n = t->n_srv < N2SL_MAX_SRV ? t->n_srv : N2SL_MAX_SRV;
		int best = -1, best_has = 0, best_left = 0;
		float best_cost = 0.0f;
		for (uint32_t i = 0; i < n; i++) {
			if (!alive[i])
				continue;
			const n2sl_srv_t *s = &t->srv[i];
			uint32_t used = __atomic_load_n(&a->assigned[i], __ATOMIC_RELAXED) - s->base_assigned;
			uint32_t k = used > N2SL_KMAX ? N2SL_KMAX : used;
			float c = s->cost[k + 1];
			int left = s->seats - (int)used;
			int has = left > 0;
			if (best < 0 || has > best_has ||
			    (has == best_has && (c < best_cost - 1e-6f ||
			                         (fabsf(c - best_cost) <= 1e-6f && left > best_left)))) {
				best = (int)i; best_has = has; best_cost = c; best_left = left;
			}
		}
		__atomic_thread_fence(__ATOMIC_ACQUIRE);
		if (__atomic_load_n(&t->seq, __ATOMIC_RELAXED) != s1)
			continue;                    /* 읽는 중에 표가 바뀜 → 다시 */
		if (best >= 0)
			__atomic_fetch_add(&a->assigned[best], 1u, __ATOMIC_RELAXED);
		return best;
	}
	return -1;
}

#endif
