#ifndef __NETRACE_COM_H
#define __NETRACE_COM_H

#ifndef likely
#define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif

#ifndef min
#define min(x, y) ({                		\
    typeof(x) _min1 = (x);			\
    typeof(y) _min2 = (y);			\
    (void) ((void *)&_min1 == (void *)&_min2);	\
    _min1 < _min2 ? _min1 : _min2; })
#endif

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */

enum event_type {
	/* order matters! DO NOT change the order */
	EVENT_TYPE_NET_TX_SOFTIRQ = 0,
	EVENT_TYPE_NET_RX_SOFTIRQ,

	/* MUST be a power of 2 */
	__EVENT_TYPE_MAX = 2,
};
#define EVENT_TYPE_MAX (__EVENT_TYPE_MAX - 1)

struct pcpu_info {
	__u64 entry_ts;
	__u64 event_total_time[EVENT_TYPE_MAX + 1];
	__u64 last_delay_ns;                       // Delay آخرین softirq (ns)
	__u64 delay_total;                         // مجموع delayها (ns)
	__u64 delay_count;                         // تعداد delay (برای avg)
	__u64 event_counts[EVENT_TYPE_MAX + 1];    // شمارنده رخدادها (برای هر event)
};

#endif /* __NETRACE_H */

