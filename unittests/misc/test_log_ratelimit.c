/* 	$OpenBSD$ */
/*
 * Regress test for log_log_ratelimit()
 *
 * Placed in the public domain.
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "test_helper.h"

#include "log.h"

void test_log_ratelimit(void);

void
test_log_ratelimit(void)
{
	struct log_ratelimit_ctx rl;
	int r, i, active;
	time_t now;
	u_int n;

	log_ratelimit_init(&rl, 4, 20, 10, 5);
	now = time(NULL);

	TEST_START("ratelimit below threshold");
	r = log_ratelimit(&rl, now, &active, NULL);
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(active, 0);
	r = log_ratelimit(&rl, now, &active, NULL);
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(active, 0);
	r = log_ratelimit(&rl, now, &active, NULL);
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(active, 0);
	TEST_DONE();

	/* should be ratelimited */
	TEST_START("ratelimit above threshold");
	r = log_ratelimit(&rl, now, &active, NULL);
	ASSERT_INT_EQ(r, 1);
	ASSERT_INT_EQ(active, 1);
	TEST_DONE();

	TEST_START("another above threshold");
	r = log_ratelimit(&rl, now, &active, NULL);
	ASSERT_INT_EQ(r, 1);
	ASSERT_INT_EQ(active, 1);
	TEST_DONE();

	/* keep events going until log_every due */
	TEST_START("more events over time");
	for (i = 0; i < 4; i++) {
		r = log_ratelimit(&rl, ++now, &active, NULL);
		ASSERT_INT_EQ(r, 1);
		ASSERT_INT_EQ(active, 1);
	}
	TEST_DONE();

	/* next event should be allowed */
	TEST_START("allow periodic");
	r = log_ratelimit(&rl, ++now, &active, &n);
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(n, 6);
	ASSERT_INT_EQ(active, 1);
	TEST_DONE();

	TEST_START("non periodic");
	r = log_ratelimit(&rl, ++now, &active, NULL);
	ASSERT_INT_EQ(r, 1);
	ASSERT_INT_EQ(active, 1);
	TEST_DONE();

	TEST_START("expire accum");
	now += 7; /* all events expired */
	r = log_ratelimit(&rl, ++now, &active, &n);
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(n, 1);
	ASSERT_INT_EQ(active, 1);
	TEST_DONE();

	TEST_START("in hysteresis");
	now += 3; /* still in hysteresis */
	r = log_ratelimit(&rl, ++now, &active, NULL);
	ASSERT_INT_EQ(n, 1);
	ASSERT_INT_EQ(active, 1);
	TEST_DONE();

	/* terminate hysteresis before it expires */
	TEST_START("restart from hysteresis");
	for (i = 0; i < 4; i++) {
		r = log_ratelimit(&rl, now, &active, NULL);
		ASSERT_INT_EQ(r, 1);
		ASSERT_INT_EQ(active, 1);
	}
	TEST_DONE();

	/* go back into hysteresis */
	TEST_START("start hysteresis");
	now += 8;
	r = log_ratelimit(&rl, ++now, &active, &n);
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(n, 5);
	ASSERT_INT_EQ(active, 1);
	TEST_DONE();

	/* expire hysteresis */
	TEST_START("expire hysteresis");
	now += 11;
	r = log_ratelimit(&rl, now, &active, NULL);
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(active, 0);
	TEST_DONE();

	/* restart ratelimit */
	now += 4;
	TEST_START("restart ratelimit");
	for (i = 0; i < 3; i++) {
		r = log_ratelimit(&rl, now, &active, NULL);
		ASSERT_INT_EQ(r, 0);
		ASSERT_INT_EQ(active, 0);
	}
	r = log_ratelimit(&rl, now, &active, NULL);
	ASSERT_INT_EQ(r, 1);
	ASSERT_INT_EQ(active, 1);
	TEST_DONE();

	/* preexpire hysteresis */
	TEST_START("preexpire hysteresis");
	now += 20;
	r = log_ratelimit(&rl, now, &active, NULL);
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(active, 0);
	TEST_DONE();

	/* XXX need test for max_accum */
}
