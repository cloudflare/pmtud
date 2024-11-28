// PMTUD
//
// Copyright (c) 2015 CloudFlare, Inc.

#include <sched.h>

int taskset(int taskset_cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(taskset_cpu, &set);
	return sched_setaffinity(0, sizeof(cpu_set_t), &set);
}
