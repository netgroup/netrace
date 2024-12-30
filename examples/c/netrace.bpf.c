
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#include "netrace.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct pcpu_info));
	__uint(max_entries, 1);
} pcpu SEC(".maps");

#ifdef DEBUG
/* only for debug purposes */
static __always_inline char *softirq_vec_to_name(unsigned int vec)
{
	switch (vec) {
		case HI_SOFTIRQ:
			return "HI_SOFTIRQ";
		case TIMER_SOFTIRQ:
			return "TIMER_SOFTIRQ";
		case NET_TX_SOFTIRQ:
			return "NET_TX_SOFTIRQ";
		case NET_RX_SOFTIRQ:
			return "NET_RX_SOFTIRQ";
		case BLOCK_SOFTIRQ:
			return "BLOCK_SOFTIRQ";
		case IRQ_POLL_SOFTIRQ:
			return "IRQ_POLL_SOFTIRQ";
		case TASKLET_SOFTIRQ:
			return "TASKLET_SOFTIRQ";
		case SCHED_SOFTIRQ:
			return "SCHED_SOFTIRQ";
		case HRTIMER_SOFTIRQ:
			return "HRTIMER_SOFTIRQ";
		case RCU_SOFTIRQ:
			return "RCU_SOFTIRQ";
		default:
			return "UNKNOWN";
	};
}

static __always_inline int print_softirq_name(unsigned int vec)
{
	char *vname = softirq_vec_to_name(vec);

	if (unlikely(!vname))
		return -EINVAL;

	bpf_printk("net_softirq vec=%d, name=%s", vec, vname);

	return 0;
}
#endif /* DEBUG */

static __always_inline struct pcpu_info *pcpu_info_get(void)
{
	const u32 key = 0;

	return bpf_map_lookup_elem(&pcpu, &key);
}

static __always_inline u64 timestamp_get_ns(void)
{
	return bpf_ktime_get_ns();
}

static __always_inline void record_timestamp(struct pcpu_info *pinfo)
{
	pinfo->entry_ts = timestamp_get_ns();
}

static __always_inline
void __softirq_net_update_event_total_time(struct pcpu_info *pinfo,
					   unsigned int vec)
{
	unsigned int voffset;
	u64 delta_ns;
	int index;

	/* branchless as we already check in the caller that vec can be only
	 * NET_{TX,RX}_SOFTIRQ.
	 * NET_{TX,RX}_SOFTIRQ and EVENT_TYPE_NET_{TX,RX}_SOFTIRQ are ordered
	 * in the same way. For this reason we can use relative offset to
	 * convert one into another.
	 */
	voffset = vec - NET_TX_SOFTIRQ;
	index = (EVENT_TYPE_NET_TX_SOFTIRQ + voffset) & EVENT_TYPE_MAX;

	delta_ns = timestamp_get_ns() - pinfo->entry_ts;
	pinfo->event_total_time[index] += delta_ns;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(net_softirq_entry, unsigned int vec)
{
	struct pcpu_info *pinfo;

	if (vec != NET_RX_SOFTIRQ && vec != NET_TX_SOFTIRQ)
		return 0;

	pinfo = pcpu_info_get();
	if (unlikely(!pinfo))
		return 0;

	record_timestamp(pinfo);

	return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(net_softirq_exit, unsigned int vec)
{
	struct pcpu_info *pinfo;

	if (vec != NET_RX_SOFTIRQ && vec != NET_TX_SOFTIRQ)
		return 0;

	pinfo = pcpu_info_get();
	if (unlikely(!pinfo))
		return 0;

	__softirq_net_update_event_total_time(pinfo, vec);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
