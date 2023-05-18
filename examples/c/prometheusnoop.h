/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Red Hat */
#ifndef __PROMETHEUSSNOOP_H
#define __PROMETHEUSSNOOP_H

#include <stdbool.h>

struct event {
	void *object;
	uint64_t value;
	int pid;
	bool float_value;
	// This can be further optimized by taking advantage of Go's string type
	// that comes with the string length.
	char description[64];
};

#endif /* __PROMETHEUSSNOOP_H */
