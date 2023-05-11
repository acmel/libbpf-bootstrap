/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Red Hat */
#ifndef __PROMETHEUSSNOOP_H
#define __PROMETHEUSSNOOP_H

enum metric_event {
	EV_counterInc,
	EV_gaugeAdd,
	EV_gaugeDec,
	EV_gaugeInc,
	EV_gaugeSub,
};

struct event {
	void *object;
	int pid;
	enum metric_event event;
	uint64_t value;
	// This can be further optimized by taking advantage of Go's string type
	// that comes with the string length.
	char description[64];
};

#endif /* __PROMETHEUSSNOOP_H */
