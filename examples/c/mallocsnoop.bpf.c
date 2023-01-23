// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mallocsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct malloc_entry {
	u64 ts;
	size_t size;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, pid_t);
	__type(value, struct malloc_entry);
} malloc_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long my_pid = 0;
const volatile unsigned long long min_duration_ns = 0;

// Remember what was malloc's 'size' argument for this pid
SEC("uprobe/libc.so.6:malloc")
int BPF_UPROBE(malloc_in, size_t size)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (pid == my_pid)
		return 0;

	struct malloc_entry entry = {
		.ts   = bpf_ktime_get_ns(),
		.size = size,
	};

	bpf_map_update_elem(&malloc_start, &pid, &entry, BPF_ANY);

	return 0;
}

SEC("uretprobe/libc.so.6:malloc")
int BPF_URETPROBE(malloc_out, void *addr) // addr returned by malloc
{
	struct event *e;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (pid == my_pid)
		return 0;

        /* don't emit malloc events when minimum duration is specified */
        if (min_duration_ns)
                return 0;

	struct malloc_entry *entry = bpf_map_lookup_elem(&malloc_start, &pid);

	if (entry == NULL)
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->free_event = false;
	e->pid = pid;
	e->addr = addr;
	e->size = entry->size;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("uprobe/libc.so.6:free")
int BPF_UPROBE(handle_free, void *addr)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (pid == my_pid)
		return 0;

	struct malloc_entry *entry = bpf_map_lookup_elem(&malloc_start, &pid);

	if (entry == NULL)
		return 0;

	u64 duration_ns = bpf_ktime_get_ns() - entry->ts;

        if (min_duration_ns && duration_ns < min_duration_ns)
                return 0;

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->free_event = true;
	e->pid = pid;
	e->addr = addr;
	e->duration_ns = duration_ns;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_map_delete_elem(&malloc_start, &pid);

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
