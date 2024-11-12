/* 	$OpenBSD: tests.c,v 1.1 2015/02/16 22:18:34 djm Exp $ */
/*
 * Regress test for known_hosts-related API.
 *
 * Placed in the public domain
 */

#include <stdio.h>

#include "test_helper.h"

void tests(void);
void test_iterate(void); /* test_iterate.c */

void
tests(void)
{
	test_iterate();
}

void
benchmarks(void)
{
	printf("no benchmarks\n");
}
