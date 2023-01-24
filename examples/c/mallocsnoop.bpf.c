// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Red Hat */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mallocsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct alloc_entry {
	u64 ts;
	size_t size;
	size_t nmemb;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, pid_t);
	__type(value, struct alloc_entry);
} alloc_start SEC(".maps");

struct alloc_addrs_key {
	u64  pid; // Not pid_t (32 bits) to avoid a struct alignment hole, the verifier will refuse loading in that case.
	void *addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct alloc_addrs_key);
	__type(value, struct alloc_entry);
} alloc_addrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long my_pid = 0;
const volatile unsigned long target_pid = 0;
const volatile unsigned long min_size = 0;
const volatile unsigned long max_size = 0;
const volatile unsigned long long min_duration_ns = 0;

static int alloc_in(size_t nmemb, size_t size)
{
	unsigned long total_size = nmemb * size;

	if ((min_size && total_size < min_size) ||
	    (max_size && total_size > max_size))
		return 0;

	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (pid == my_pid || (target_pid && pid != target_pid))
		return 0;

	struct alloc_entry entry = {
		.ts   = bpf_ktime_get_ns(),
		.nmemb = nmemb,
		.size = size,
	};

	bpf_map_update_elem(&alloc_start, &pid, &entry, BPF_ANY);

	return 0;
}

static int alloc_out(enum alloc_event alloc_event, void *addr) // addr returned by malloc/calloc/etc
{
	// malloc/calloc/etc() failed, returning NULL
	if (!addr)
		return 0;

	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (pid == my_pid || (target_pid && pid != target_pid))
		return 0;

	struct alloc_entry *entry = bpf_map_lookup_elem(&alloc_start, &pid);

	if (!entry)
		return 0;

	struct alloc_addrs_key addrs_key = {
		.addr = addr,
		.pid  = pid,
	};
	struct alloc_entry chunk = {
		.nmemb = entry->nmemb,
		.size = entry->size,
		.ts   = entry->ts,
	};

	bpf_map_update_elem(&alloc_addrs, &addrs_key, &chunk, BPF_ANY);
	bpf_map_delete_elem(&alloc_start, &pid);

        /* don't emit malloc events when minimum duration is specified */
        if (min_duration_ns)
                return 0;

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->event = alloc_event;
	e->pid = pid;
	e->addr = addr;
	e->nmemb = chunk.nmemb;
	e->size = chunk.size;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Remember what was malloc's 'size' argument for this pid
SEC("uprobe/libc.so.6:malloc")
int BPF_UPROBE(malloc_in, size_t size)
{
	return alloc_in(1, size);
}

// Now that we're exiting malloc, we need to create an entry using
// the returned address and the pid_t that allocated it as the key
// so that at free() time we can do the math
SEC("uretprobe/libc.so.6:malloc")
int BPF_URETPROBE(malloc_out, void *addr) // addr returned by malloc
{
	return alloc_out(EV_MALLOC, addr);
}

SEC("uprobe/libc.so.6:calloc")
int BPF_UPROBE(calloc_in, size_t nmemb, size_t size)
{
	return alloc_in(nmemb, size);
}

SEC("uretprobe/libc.so.6:calloc")
int BPF_URETPROBE(calloc_out, void *addr) // addr returned by calloc
{
	return alloc_out(EV_CALLOC, addr);
}

SEC("uprobe/libc.so.6:free")
int BPF_UPROBE(handle_free, void *addr)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (pid == my_pid || (target_pid && pid != target_pid))
		return 0;

	struct alloc_addrs_key addrs_key = {
		.addr = addr,
		.pid  = pid,
	};
	struct alloc_entry *chunk = bpf_map_lookup_elem(&alloc_addrs, &addrs_key);

	if (chunk == NULL)
		return 0;

	u64 duration_ns = bpf_ktime_get_ns() - chunk->ts;

        if (min_duration_ns && duration_ns < min_duration_ns)
                return 0;

	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->event = EV_FREE;
	e->pid = pid;
	e->addr = addr;
	e->nmemb = chunk->nmemb;
	e->size = chunk->size;
	e->duration_ns = duration_ns;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_map_delete_elem(&alloc_addrs, &addrs_key);

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
