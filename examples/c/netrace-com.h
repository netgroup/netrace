#ifndef __NETRACE_COM_H   // [refactor] - updated header guard for new filename
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

// -------------------------------------------------------------------
// Event types for network softirq processing.
// The order must NOT be changed (used for direct indexing).
// -------------------------------------------------------------------
enum event_type {
	/* order matters! DO NOT change the order */
	EVENT_TYPE_NET_TX_SOFTIRQ = 0,
	EVENT_TYPE_NET_RX_SOFTIRQ,

	/* MUST be a power of 2 */
	__EVENT_TYPE_MAX = 2,
};
#define EVENT_TYPE_MAX (__EVENT_TYPE_MAX - 1)

// -------------------------------------------------------------------
// Per-CPU statistics structure for softirq processing monitoring.
// Extended to support detailed delay analysis and event counting.
// -------------------------------------------------------------------
struct pcpu_info {
	__u64 entry_ts;                           // Timestamp of last softirq entry (ns)
	__u64 event_total_time[EVENT_TYPE_MAX + 1]; // Cumulative total processing time per softirq event type (ns)

	__u64 last_delay_ns;                      // [feat] Last observed processing delay for the most recent softirq event (ns)
	__u64 delay_total;                        // [feat] Cumulative sum of all observed delays per CPU (ns), for averaging
	__u64 delay_count;                        // [feat] Number of delay samples observed per CPU (for computing average delay)
	__u64 event_counts[EVENT_TYPE_MAX + 1];   // [feat] Per-event-type counter: how many times each softirq type has occurred on this CPU
};

#endif /* __NETRACE_COM_H */
