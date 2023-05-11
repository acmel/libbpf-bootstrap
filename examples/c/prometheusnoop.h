/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Red Hat */
#ifndef __PROMETHEUSSNOOP_H
#define __PROMETHEUSSNOOP_H

enum metric_event {
	EV_COUNTER_INC,
	EV_GAUGE_ADD,
	EV_GAUGE_INC,
};

struct event {
	void *object;
	int pid;
	enum metric_event event;
	uint64_t value;
	int64_t increment;
	// This can be further optimized by taking advantage of Go's string type
	// that comes with the string length.
	char description[64];
};

#endif /* __PROMETHEUSSNOOP_H */
