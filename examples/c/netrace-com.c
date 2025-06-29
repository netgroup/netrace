#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <cjson/cJSON.h>

// [HEADER] - Switch to netrace-com skeleton and header (refactor)
#include "netrace-com.skel.h"   // Uses the new skeleton matching updated BPF
#include "netrace-com.h"        // Uses the new header with extended struct

#define INTERVAL_IN_SEC		1
#define LOAD_PERC_TH		((double)0.01)
#define BUF_SIZE		32

static volatile sig_atomic_t stop;

static const char *event_names[EVENT_TYPE_MAX + 1] = {
	[EVENT_TYPE_NET_TX_SOFTIRQ] = "EVENT_NET_TX_SOFTIRQ",
	[EVENT_TYPE_NET_RX_SOFTIRQ] = "EVENT_NET_RX_SOFTIRQ",
};

static const char *event_to_name(enum event_type event)
{
	if (event >= EVENT_TYPE_MAX + 1)
		return NULL;
	return event_names[event];
}

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	stop = 1;
}

// [RECORD STRUCT] - Add per-CPU delay and average fields for delay tracking (feat)
struct record {
	__u64 ts;
	__u64 *pcpu_event_total_time[EVENT_TYPE_MAX + 1];
	__u64 *pcpu_last_delay_ns;   // Latest observed delay per CPU (ns)
	__u64 *pcpu_delay_total;     // Cumulative delay per CPU (for avg)
	__u64 *pcpu_delay_count;     // Number of delay samples per CPU
};

static double eval_period(struct record *cur, struct record *prev)
{
	double period = 0;
	__s64 _period = 0;

	_period = cur->ts - prev->ts;
	if (_period > 0)
		period = ((double)_period) / NANOSEC_PER_SEC;
	return period;
}

static int map_get_value_pcpu_array(int fd, __u32 key, struct record *rec)
{
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct pcpu_info pinfos[nr_cpus];
	int rc, event_idx, cpu_idx;
	__u64 *pcpu_tt;

	rc = bpf_map_lookup_elem(fd, &key, pinfos);
	if (rc) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return rc;
	}

	// [MAP FILL] - Fill standard and delay statistics from BPF map (feat)
	for (event_idx = 0; event_idx < EVENT_TYPE_MAX + 1; ++event_idx) {
		pcpu_tt = rec->pcpu_event_total_time[event_idx];
		for (cpu_idx = 0; cpu_idx < nr_cpus; ++cpu_idx)
			pcpu_tt[cpu_idx] = pinfos[cpu_idx].event_total_time[event_idx];
	}
	// [MAP FILL] - New: Populate delay/avg statistics from BPF to user-space (feat)
	for (cpu_idx = 0; cpu_idx < nr_cpus; ++cpu_idx) {
		rec->pcpu_last_delay_ns[cpu_idx] = pinfos[cpu_idx].last_delay_ns;
		rec->pcpu_delay_total[cpu_idx]   = pinfos[cpu_idx].delay_total;
		rec->pcpu_delay_count[cpu_idx]   = pinfos[cpu_idx].delay_count;
	}

	return 0;
}

static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAILURE);
	}

	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static int stat_collect(int fd, __u32 key, struct record *rec)
{
	rec->ts = gettime();
	return map_get_value_pcpu_array(fd, key, rec);
}

// [ALLOC/FREE] - Free memory for per-CPU delay fields (fix)
static void free_record(struct record *rec)
{
	__u64 *pcpu_tt;
	int i;

	if (!rec)
		return;

	for (i = 0; i < EVENT_TYPE_MAX + 1; ++i) {
		pcpu_tt = rec->pcpu_event_total_time[i];
		if (pcpu_tt)
			free(pcpu_tt);
	}
	if (rec->pcpu_last_delay_ns) free(rec->pcpu_last_delay_ns);
	if (rec->pcpu_delay_total) free(rec->pcpu_delay_total);
	if (rec->pcpu_delay_count) free(rec->pcpu_delay_count);

	free(rec);
}

// [ALLOC/FREE] - Allocate memory for per-CPU delay fields (fix)
static struct record *alloc_record(void)
{
	unsigned int nr_cpus;
	struct record *rec;
	__u64 *pcpu_tt;
	int i;

	rec = calloc(1, sizeof(*rec));
	if (!rec)
		return NULL;

	nr_cpus = libbpf_num_possible_cpus();
	for (i = 0; i < EVENT_TYPE_MAX + 1; ++i) {
		pcpu_tt = calloc(1, nr_cpus * sizeof(*pcpu_tt));
		if (!pcpu_tt)
			goto cleanup;
		rec->pcpu_event_total_time[i] = pcpu_tt;
	}
	rec->pcpu_last_delay_ns = calloc(1, nr_cpus * sizeof(__u64));
	rec->pcpu_delay_total = calloc(1, nr_cpus * sizeof(__u64));
	rec->pcpu_delay_count = calloc(1, nr_cpus * sizeof(__u64));
	if (!rec->pcpu_last_delay_ns || !rec->pcpu_delay_total || !rec->pcpu_delay_count)
		goto cleanup;

	return rec;

cleanup:
	free_record(rec);
	return NULL;
}

static void swap_ref(struct record **a, struct record **b)
{
	struct record *tmp;
	tmp = *a;
	*a = *b;
	*b = tmp;
}

static double eval_load_perc(__u64 val_ns, double period)
{
	return ((val_ns / (double)NANOSEC_PER_SEC) / period) * 100.0;
}

// [PRINT] - Print per-CPU last and average delay (feat)
static void stats_print(struct record *prev, struct record *rec)
{
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	__u64 *pcpu_tt_prev, *pcpu_tt_rec;
	int event_idx, cpu_idx;
	double period, load;
	__s64 tdiff_ns;

	period = eval_period(rec, prev);
	if (period == 0)
		return;

	for (event_idx = 0; event_idx < EVENT_TYPE_MAX + 1; ++event_idx) {
		printf("=== %s ===\n", event_to_name(event_idx));
		pcpu_tt_prev = prev->pcpu_event_total_time[event_idx];
		pcpu_tt_rec = rec->pcpu_event_total_time[event_idx];

		for (cpu_idx = 0; cpu_idx < nr_cpus; ++cpu_idx) {
			tdiff_ns  = pcpu_tt_rec[cpu_idx] - pcpu_tt_prev[cpu_idx];
			load = eval_load_perc(tdiff_ns, period);
			if (load < LOAD_PERC_TH)
				continue;
			// Print delay and avg delay per CPU (ms)
			double last_delay_ms = (double)rec->pcpu_last_delay_ns[cpu_idx] / 1e6;
			double avg_delay_ms = 0;
			if (rec->pcpu_delay_count[cpu_idx])
				avg_delay_ms = (double)rec->pcpu_delay_total[cpu_idx] / rec->pcpu_delay_count[cpu_idx] / 1e6;
			printf("CPU %2d | Load: %6.2f%% | Last delay: %8.3f ms | Avg delay: %8.3f ms\n",
				cpu_idx, load, last_delay_ms, avg_delay_ms);
		}
	}
	fflush(stdout);
}

static int stats_poll(int fd, int interval)
{
	struct record *prev, *rec;
	const int key = 0;
	int rc;

	prev = alloc_record();
	rec = alloc_record();
	if (!prev || !rec) {
		rc = -ENOMEM;
		goto cleanup;
	}

	rc = stat_collect(fd, key, rec);
	if (rc)
		goto cleanup;

	sleep(interval);

	while (!stop) {
		swap_ref(&prev, &rec);
		rc = stat_collect(fd, key, rec);
		if (rc)
			goto cleanup;

		stats_print(prev, rec);

		sleep(interval);
	}

	rc = 0;

cleanup:
	free_record(rec);
	free_record(prev);

	return rc;
}

// [MAIN] - Update skeleton usage to netrace_com_bpf (refactor)
int main(int argc, char **argv)
{
	struct netrace_com_bpf *skel;    // Use the new skeleton type
	int pcpu_fd;
	int err;

	libbpf_set_print(libbpf_print_fn);

	skel = netrace_com_bpf__open_and_load();   // Open skeleton with new name
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = netrace_com_bpf__attach(skel);       // Attach skeleton with new name
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n",
			strerror(errno));
		goto cleanup;
	}

	pcpu_fd = bpf_map__fd(skel->maps.pcpu);
	if (!pcpu_fd) {
		fprintf(stderr, "can't open FD for pcpu map\n");
		goto cleanup;
	}

	fprintf(stderr,
		"Successfully started! Press Ctrl+C to stop.\n");

	stats_poll(pcpu_fd, INTERVAL_IN_SEC);
	err = 0;

cleanup:
	netrace_com_bpf__destroy(skel);    // Destroy skeleton with new name
	return -err;
}
