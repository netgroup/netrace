#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#include "netrace-com.h"

// -------------------------------------------------------------
// BPF per-CPU map for statistics
// This map stores, for each CPU, a struct pcpu_info containing
// softirq timing stats and latest delay measurements.
//
// - Type: BPF_MAP_TYPE_PERCPU_ARRAY
// - Key:  u32 (only key = 0 is used)
// - Value: struct pcpu_info (per CPU)
//
// This ensures that all stats are kept separately for each CPU core.
// -------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct pcpu_info));
    __uint(max_entries, 1);
} pcpu SEC(".maps");

#ifdef DEBUG
/* Debug utilities: Print softirq type names to trace_pipe */
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

    // Output to /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("net_softirq vec=%d, name=%s", vec, vname);

    return 0;
}
#endif /* DEBUG */

// ------------------------------------------------------------------
// Helper: Fetch the per-CPU statistics struct from the map.
// Always uses key = 0 (single entry per CPU).
// ------------------------------------------------------------------
static __always_inline struct pcpu_info *pcpu_info_get(void)
{
    const u32 key = 0;
    return bpf_map_lookup_elem(&pcpu, &key);
}

// ------------------------------------------------------------------
// Helper: Read high-resolution current time in nanoseconds.
// ------------------------------------------------------------------
static __always_inline u64 timestamp_get_ns(void)
{
    return bpf_ktime_get_ns();
}

// ------------------------------------------------------------------
// Save the timestamp at the entry point of a softirq for the current CPU.
// ------------------------------------------------------------------
static __always_inline void record_timestamp(struct pcpu_info *pinfo)
{
    pinfo->entry_ts = timestamp_get_ns();
}

// ------------------------------------------------------------------
// Update statistics for the current softirq:
//  - Compute processing delay (delta_ns)
//  - Add to cumulative total time
//  - Record the latest delay (for user-space monitoring)
// This enables user-space to observe both total time and the most recent
// softirq handling delay for each event type.
// ------------------------------------------------------------------
static __always_inline
void __softirq_net_update_event_total_time(struct pcpu_info *pinfo,
                                           unsigned int vec)
{
    unsigned int voffset;
    u64 delta_ns;
    int index;

    // Map the softirq vector to event_type index.
    voffset = vec - NET_TX_SOFTIRQ;
    index = (EVENT_TYPE_NET_TX_SOFTIRQ + voffset) & EVENT_TYPE_MAX;

    // Calculate processing delay: time since entry.
    delta_ns = timestamp_get_ns() - pinfo->entry_ts;

    // Add to cumulative total time for this softirq type.
    pinfo->event_total_time[index] += delta_ns;

    // Store the most recent processing delay for this softirq event.
    // This value can be reported to user-space for delay analysis.
    pinfo->last_delay_ns = delta_ns;
}

// ------------------------------------------------------------------
// Tracepoint: softirq_entry
// Save timestamp on softirq entry (for TX/RX only).
// ------------------------------------------------------------------
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

// ------------------------------------------------------------------
// Tracepoint: softirq_exit
// Update cumulative and last delay on softirq exit (for TX/RX only).
// ------------------------------------------------------------------
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

// License for BPF program
char LICENSE[] SEC("license") = "Dual BSD/GPL";
