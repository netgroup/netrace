
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "netrace.skel.h"

#include "netrace.h"

#define INTERVAL_IN_SEC		1
#define LOAD_PERC_TH		((double)0.01)

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

struct record {
	__u64 ts;
	/* per-cpu dyn allocated */
	__u64 *pcpu_event_total_time[EVENT_TYPE_MAX + 1];
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

	/* for each different event, let's copy the pcpu counters */
	for (event_idx = 0; event_idx < EVENT_TYPE_MAX + 1; ++event_idx) {
		/* pointer to the pcpu counters for the given event type */
		pcpu_tt = rec->pcpu_event_total_time[event_idx];

		for (cpu_idx = 0; cpu_idx < nr_cpus; ++cpu_idx)
			pcpu_tt[cpu_idx] = pinfos[cpu_idx].event_total_time[event_idx];
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
	/* retrieve time as close as possibile to reading map contents */
	rec->ts = gettime();

	return map_get_value_pcpu_array(fd, key, rec);
}

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

	free(rec);
}

static struct record *alloc_record(void)
{
	unsigned int nr_cpus;
	struct record *rec;
	__u64 *pcpu_tt;
	int i;

	rec = calloc(1, sizeof(*rec));
	if (!rec)
		return NULL;

	/* now we allocate the required space for all cpus considering each
	 * different event.
	 */
	nr_cpus = libbpf_num_possible_cpus();
	for (i = 0; i < EVENT_TYPE_MAX + 1; ++i) {
		pcpu_tt = calloc(1, nr_cpus * sizeof(*pcpu_tt));
		if (!pcpu_tt)
			goto cleanup;

		rec->pcpu_event_total_time[i] = pcpu_tt;
	}

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
		const char *event_name = event_to_name(event_idx);

		/* pointer to the pcpu counters for the given event type */
		pcpu_tt_prev = prev->pcpu_event_total_time[event_idx];
		pcpu_tt_rec = rec->pcpu_event_total_time[event_idx];

		for (cpu_idx = 0; cpu_idx < nr_cpus; ++cpu_idx) {
			tdiff_ns  = pcpu_tt_rec[cpu_idx] -
				    pcpu_tt_prev[cpu_idx];

			load = eval_load_perc(tdiff_ns, period);
			if (load < LOAD_PERC_TH)
				continue;

			fprintf(stdout, "event:%s - cpu[%d]:%f\n",
				event_name, cpu_idx, load);
		}
	}
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

	/* collect initial measurements */
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

int main(int argc, char **argv)
{
	struct netrace_bpf *skel;
	int pcpu_fd;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = netrace_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = netrace_bpf__attach(skel);
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

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	stats_poll(pcpu_fd, INTERVAL_IN_SEC);
	/* TODO: return the rc of stats_poll ? */
	err = 0;

cleanup:
	netrace_bpf__destroy(skel);
	return -err;
}
