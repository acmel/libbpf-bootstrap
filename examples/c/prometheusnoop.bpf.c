// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Started from the libbpf-bootstrap examples/c/bootstrap.bpf.c
/* Copyright (c) 2022 Red Hat */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "prometheusnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long my_pid = 0;
const volatile unsigned long target_pid = 0;
const volatile unsigned long exclude_pid = 0;

// exclude_pid to avoid feedback loops, like when running mallocsnoop on
// a gnome-terminal that allocates/frees when printing stuff then generates
// events caught by mallocsnoop that prints, generating the loop.
static bool filtered_pid(pid_t pid)
{
	return pid == my_pid || (target_pid && pid != target_pid) || (exclude_pid && pid == exclude_pid);
}

#if 0
# pahole -C string main
struct string {
	uint8 *                    str;                  /*     0     8 */
	int                        len;                  /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};

# pahole -C github.com/prometheus/client_golang/prometheus.Desc main
struct github.com/prometheus/client_golang/prometheus.Desc {
	struct string              fqName;               /*     0    16 */
	struct string              help;                 /*    16    16 */
	struct []*github.com/prometheus/client_model/go.LabelPair constLabelPairs; /*    32    24 */
	struct []string            variableLabels;       /*    56    24 */
	/* --- cacheline 1 boundary (64 bytes) was 16 bytes ago --- */
	uint64                     id;                   /*    80     8 */
	uint64                     dimHash;              /*    88     8 */
	error                      err;                  /*    96    16 */

	/* size: 112, cachelines: 2, members: 7 */
	/* last cacheline: 48 bytes */
};
#endif

typedef struct {
	const char	*str;	  /*     0     8 */
	int		len;	  /*     8     8 */
} string;

typedef struct {
	string		fqName;	  /*     0    16 */
} github_com_prometheus_client_golang_prometheus_Desc;

#if 0
# pahole -C github.com/prometheus/client_golang/prometheus.counter main
struct github.com/prometheus/client_golang/prometheus.counter {
	uint64                     valBits;              /*     0     8 */
	uint64                     valInt;               /*     8     8 */
	github.com/prometheus/client_golang/prometheus.selfCollector selfCollector; /*    16    16 */
	github.com/prometheus/client_golang/prometheus.Desc * desc; /*    32     8 */
	struct []*github.com/prometheus/client_model/go.LabelPair labelPairs; /*    40    24 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	sync/atomic.Value          exemplar;             /*    64    16 */
	func() time.Time           now;                  /*    80     8 */

	/* size: 88, cachelines: 2, members: 7 */
	/* last cacheline: 24 bytes */
};

#
#endif

typedef struct {
	uint64_t   valBits;     /*     0     8 */
	uint64_t   valInt;      /*     8     8 */
	uint64_t   selfCollector[2]; /* github.com/prometheus/client_golang/prometheus.selfCollector */ /*    16    16 */
	github_com_prometheus_client_golang_prometheus_Desc *desc; /*    32     8 */
} github_com_prometheus_client_golang_prometheus_counter;

static inline int counter_read(struct event *e, int value_offset,
			       int desc_offset,
			       struct pt_regs *regs)
{
	if (bpf_probe_read_user(&e->value, sizeof(e->value), (void *)regs->ax + value_offset) < 0)
		return -11111111;

	github_com_prometheus_client_golang_prometheus_Desc *prometheus_counter_desc_ptr;

	if (bpf_probe_read_user(&prometheus_counter_desc_ptr, sizeof(prometheus_counter_desc_ptr), (void *)regs->ax + desc_offset) < 0)
		return -55555555;

	github_com_prometheus_client_golang_prometheus_Desc prometheus_counter_desc = {};

	if (bpf_probe_read_user(&prometheus_counter_desc, sizeof(prometheus_counter_desc), prometheus_counter_desc_ptr) < 0)
		return -22222222;

	size_t desc_size = sizeof(e->description);
	char *desc = e->description;

	if (desc_size == 0)
		return -33333333;

	--desc_size;

	const size_t fqName_len = prometheus_counter_desc.fqName.len;

	if (desc_size > fqName_len)
		desc_size = fqName_len;

	if (bpf_probe_read_user(desc, desc_size, prometheus_counter_desc.fqName.str) < 0)
		return -44444444;

	desc[desc_size] = '\0';

	return 0;
}

static int metric_event(int value_offset, int desc_offset, bool float_value, struct pt_regs *regs)
{
	const char unknown_description[] = "unknown description";

	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (filtered_pid(pid))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = pid;
	e->object = (void *)regs->ax; // FIXME Why not have this as the first arg in the BPF_UPROBE() declaration?
	int ret = counter_read(e, value_offset, desc_offset, regs);

	if (ret < 0) {
		__builtin_memcpy(e->description, unknown_description, sizeof(unknown_description));
		e->float_value = false;
		e->value = ret;
	} else {
		e->float_value = float_value;
	}

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("uprobe") int BPF_UPROBE(counter)
{
	return metric_event(/*value_offset=*/offsetof(github_com_prometheus_client_golang_prometheus_counter, valInt),
			    /*desc_offset=*/offsetof(github_com_prometheus_client_golang_prometheus_counter, desc),
			    /*float_value=*/false, /*regs=*/ctx);
}

#if 0
$ pahole -C github.com/prometheus/client_golang/prometheus.gauge tests/prometheus/main
struct github.com/prometheus/client_golang/prometheus.gauge {
	uint64                     valBits;              /*     0     8 */
	github.com/prometheus/client_golang/prometheus.selfCollector selfCollector; /*     8    16 */
	github.com/prometheus/client_golang/prometheus.Desc * desc; /*    24     8 */
	struct []*github.com/prometheus/client_model/go.LabelPair labelPairs; /*    32    24 */

	/* size: 56, cachelines: 1, members: 4 */
	/* last cacheline: 56 bytes */
};
#endif

typedef struct {
	uint64_t   valBits;     /*     0     8 */
	uint64_t   selfCollector[2]; /* github.com/prometheus/client_golang/prometheus.selfCollector */ /*    8    16 */
	github_com_prometheus_client_golang_prometheus_Desc *desc; /*    24     8 */
} github_com_prometheus_client_golang_prometheus_gauge;

SEC("uprobe") int BPF_UPROBE(gauge)
{
	return metric_event(/*value_offset=*/offsetof(github_com_prometheus_client_golang_prometheus_gauge, valBits),
			    /*desc_offset=*/offsetof(github_com_prometheus_client_golang_prometheus_gauge, desc),
			    /*float_value=*/true, /*regs=*/ctx);
}
