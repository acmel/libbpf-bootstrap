/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Red Hat */
#ifndef __PROMETHEUSSNOOP_H
#define __PROMETHEUSSNOOP_H

#define TASK_COMM_LEN 16

enum metric_event {
	EV_COUNTER_INC,
};

struct event {
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	void *object;
	int pid;
	enum metric_event event;
	uint64_t value;
	char description[64];
};

#endif /* __PROMETHEUSSNOOP_H */
