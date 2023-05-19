// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022, 2023 Red Hat */
// Started from the libbpf-bootstrap examples/c/bootstrap.c
#include <argp.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "prometheusnoop.h"
#include "prometheusnoop.skel.h"

/*
 * prometheusnoop output example:

  [root@quaco c]# ./prometheusnoop --help
  Usage: prometheusnoop [OPTION...]
  BPF prometheusnoop application.

  It traces prometheus metric updates

  USAGE: ./prometheusnoop [-v]

    -b, --binary=BINARY        pathname or binary name in $PATH
    -p, --pid=PID              pid to trace
    -d, --include_description  include the metric description in each event
    -v, --verbose              Verbose debug output
    -?, --help                 Give this help list
        --usage                Give a short usage message
    -V, --version              Print program version

  Mandatory or optional arguments to long options are also mandatory or optional
  for any corresponding short options.

  Report bugs to <acme@kernel.org>.
  [root@quaco c]#
*/

static struct env {
	bool verbose,
	     include_description;
	const char *binary_name;
	pid_t target_pid;
} env = {
	.target_pid = -1, // All processes if not specified.
};

const char *argp_program_version = "prometheusnoop 0.0";
const char *argp_program_bug_address = "<acme@kernel.org>";
const char argp_program_doc[] =
"BPF prometheusnoop application.\n"
"\n"
"It traces prometheus metric updates\n"
"\n"
"USAGE: ./prometheusnoop [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "binary", 'b', "BINARY", 0, "pathname or binary name in $PATH" },
	{ "pid", 'p', "PID", 0, "pid to trace" },
	{ "include_description", 'd', NULL, 0, "include the metric description in each event" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'd':
		env.include_description = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'b':
		env.binary_name = arg;
		break;
	case 'p':
		errno = 0;
		env.target_pid = strtol(arg, NULL, 10);
		if (errno || env.target_pid <= 0) {
			fprintf(stderr, "Invalid pid: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

double Float64frombits(uint64_t bits)
{
	union {
		uint64_t i;
		double f;
	} u;

	u.i = bits;
	return u.f;
}

double Float64frombits(uint64_t bits);

#ifdef USE_PERF_RING_BUFFER
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
#else
static int handle_event(void *ctx, void *data, size_t data_sz)
#endif
{
	const struct event *e = data;
	time_t t;

	time(&t);

	struct tm *tm = localtime(&t);
	char ts[32];

	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s (%p) %-7d: ", ts, e->object, e->pid);

	if (env.include_description)
		printf("desc: \"%.*s\" ", (int)sizeof(e->description), e->description);

	fputs("value: ", stdout);

	if (e->float_value)
		printf("%f\n", Float64frombits(e->value));
	else
		printf("%" PRId64 "\n", e->value);
#ifndef USE_PERF_RING_BUFFER
	return 0;
#endif
}

#ifdef USE_PERF_RING_BUFFER
void handle_lost(void *ctx __maybe_unused, int cpu, __u64 cnt)
{
	printf("LOST %" PRIu64 " events on cpu %d!\n", (uint64_t)cnt, cpu);
}
#endif

static int attach_function_to_uprobe(const char *func_name, struct bpf_program *prog, struct bpf_link **linkp,
				     bool retprobe, struct env *env, struct bpf_uprobe_opts *opts)
{
	int err = 0;

	opts->func_name = func_name;
	opts->retprobe = retprobe;
	*linkp = bpf_program__attach_uprobe_opts(/*prog=*/prog, /*pid=*/env->target_pid, /*binary_path=*/env->binary_name,
						 /*func_offset=*/0, /*opts=*/opts);
	if (!linkp) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe to function %s: %d\n", func_name, err);
	}

	return err;
}

#define prometheus_attach_class_method_to_uprobe(class_name, method_name) \
	attach_function_to_uprobe("github.com/prometheus/client_golang/prometheus.(*" #class_name ")." #method_name, \
				  skel->progs.class_name, \
				  &skel->links.class_name, false, &env, &uprobe_opts)

int main(int argc, char **argv)
{
#ifdef USE_PERF_RING_BUFFER
	struct perf_buffer *rb = NULL;
#else
	struct ring_buffer *rb = NULL;
#endif
	struct prometheusnoop_bpf *skel;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	// Default binary to monitor
	env.binary_name = "main";

	/* Parse command line arguments */
	int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = prometheusnoop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	skel->rodata->include_description = env.include_description;

	/* Load & verify BPF programs */
	err = prometheusnoop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	if (prometheus_attach_class_method_to_uprobe(counter, Inc) < 0 ||
	    prometheus_attach_class_method_to_uprobe(gauge, Add) < 0 ||
	    prometheus_attach_class_method_to_uprobe(gauge, Dec) < 0 ||
	    prometheus_attach_class_method_to_uprobe(gauge, Inc) < 0 ||
	    prometheus_attach_class_method_to_uprobe(gauge, Sub) < 0)
		goto cleanup;

	/* Attach tracepoints */
	err = prometheusnoop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
#ifdef USE_PERF_RING_BUFFER
	rb = perf_buffer__new(/*map_fd=*/bpf_map__fd(skel->maps.rb),
			      /*page_count=*/32,
			      /*sample_cb=*/handle_event,
			      /*lost_cb=*/handle_lost,
			      /*ctx=*/NULL,/*opts=*/NULL);
#else
	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
#endif
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-8s %-25s %-7s\n", "TIME", "EVENT(Object)", "PID");
	while (!exiting) {
#ifdef USE_PERF_RING_BUFFER
		err = perf_buffer__poll(rb, 100 /* timeout, ms */);
#else
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
#endif
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
#ifdef USE_PERF_RING_BUFFER
	perf_buffer__free(rb);
#else
	ring_buffer__free(rb);
#endif
	prometheusnoop_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
