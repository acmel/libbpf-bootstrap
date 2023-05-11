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
    -v, --verbose              Verbose debug output
    -X, --exclude_pid=PID      pid to filter
    -?, --help                 Give this help list
        --usage                Give a short usage message
    -V, --version              Print program version

  Mandatory or optional arguments to long options are also mandatory or optional
  for any corresponding short options.

  Report bugs to <acme@kernel.org>.
  [root@quaco c]#
*/

static struct env {
	bool verbose;
	const char *binary_name;
	pid_t target_pid;
	pid_t exclude_pid;
} env;

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
	{ "exclude_pid", 'X', "PID", 0, "pid to filter" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
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
	case 'X':
		errno = 0;
		env.exclude_pid = strtol(arg, NULL, 10);
		if (errno || env.exclude_pid <= 0) {
			fprintf(stderr, "Invalid exclude pid: %s\n", arg);
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	time_t t;

	time(&t);

	struct tm *tm = localtime(&t);
	char ts[32];

	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	switch (e->event) {
	case EV_COUNTER_INC:
		printf("%-8s %-6s(%p) %-7d: desc: \"%.*s\" value: %" PRId64 "\n", ts, "COUNTER_INC", e->object, e->pid, (int)sizeof(e->description), e->description, e->value);
		break;
	case EV_GAUGE_ADD:
		printf("%-8s %-6s(%p) %-7d: desc: \"%.*s\" value: %f\n", ts, "GAUGE_ADD", e->object, e->pid, (int)sizeof(e->description), e->description, Float64frombits(e->value));
		break;
	case EV_GAUGE_INC:
		printf("%-8s %-6s(%p) %-7d: desc: \"%.*s\" value: %f\n", ts, "GAUGE_INC", e->object, e->pid, (int)sizeof(e->description), e->description, Float64frombits(e->value));
		break;
	default:
		printf("%-8s INVALID event %d\n", ts, e->event);
	}

	return 0;
}

static int attach_function_to_uprobe(const char *func_name, struct bpf_program *prog, struct bpf_link **linkp,
				     bool retprobe, struct env *env, struct bpf_uprobe_opts *opts)
{
	int err = 0;

	opts->func_name = func_name;
	opts->retprobe = retprobe;
	*linkp = bpf_program__attach_uprobe_opts(/*prog=*/prog, /*pid=*/-1, /*binary_path=*/env->binary_name,
						 /*func_offset=*/0, /*opts=*/opts);
	if (!linkp) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe to function %s: %d\n", func_name, err);
	}

	return err;
}

#define prometheus_attach_class_method_to_uprobe(class_name, method_name) \
	attach_function_to_uprobe("github.com/prometheus/client_golang/prometheus.(*" #class_name ")." #method_name, \
				  skel->progs.class_name##method_name, \
				  &skel->links.class_name##method_name, false, &env, &uprobe_opts)

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
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

        skel->rodata->target_pid = env.target_pid;
        skel->rodata->exclude_pid = env.exclude_pid;
	skel->rodata->my_pid = getpid();

	/* Load & verify BPF programs */
	err = prometheusnoop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	if (prometheus_attach_class_method_to_uprobe(counter, Inc) < 0)
		goto cleanup;

	if (prometheus_attach_class_method_to_uprobe(gauge, Add) < 0)
		goto cleanup;

	if (prometheus_attach_class_method_to_uprobe(gauge, Inc) < 0)
		goto cleanup;

	/* Attach tracepoints */
	err = prometheusnoop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-8s %-25s %-7s\n", "TIME", "EVENT(Object)", "PID");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
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
	ring_buffer__free(rb);
	prometheusnoop_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
