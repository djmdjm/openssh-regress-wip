/* $OpenBSD$ */
/*
 * Copyright (c) 2007 Damien Miller <djm@mindrot.org>
 * Copyright (c) 2024 Google LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Tool for delaying traffic between two tun(4) interfaces.
 *
 * Note that both channel capacity and delay are bi-directional.
 * For example, requesting a 32MB capacity will require >64MB and
 * specifying a 20ms delay will result in a >40ms RTT. Note also that
 * not all of the requested capacity will be available for packets,
 * there is a little overhead; ~64bytes/packet.
 *
 * Example usage:
 *
 *  ifconfig tun0 destroy
 *  ifconfig tun1 destroy
 *  ifconfig tun1 create rdomain 100
 *  ifconfig tun0 inet 192.168.0.1 192.168.1.1
 *  ifconfig tun1 inet 192.168.1.1 192.168.0.1
 *  ./slowpipe -d 100 tun0 tun1
 *  route -T 100 exec tcpbench -s
 *  tcpbench 192.168.1.1
 *
 * I don't promise this is free of bugs - djm
 *
 * TODO: rate-limiting
 * TODO: graceful exit (drain queues)
 * TODO: assymetric delay
 * TODO: port to Linux
 * TODO: port to divert(4) sockets.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "xmalloc.h"
#include "misc.h"

extern char *__progname;

#define MAX_PACKET	65536	/* maximum packet size */
#define PACKET_ALIGN	(sizeof(void *))
#define ARENA_RESERVE	(MAX_PACKET + sizeof(struct packet) + PACKET_ALIGN)
#define STATS_INTERVAL	(10 * 1000) /* ms */

/* Tracks a packet in an arena queue */
struct packet {
	u_int magic1;
	unsigned long long id;
	u_char *d;
	size_t l;
	struct timespec due;
	size_t next_offset;
	u_int magic2;
};

/* alloc-once ring buffer for queued packets */
struct arena {
	size_t capacity;
	size_t active_bytes;
	u_char *alloc;
	size_t first_offset;
	size_t last_offset;
	unsigned long long next_id;
	unsigned long long active_packets;
	unsigned long long total_bytes;
	unsigned long long total_packets;
	u_int magic1, magic2;
};

static sig_atomic_t signum = 0;

static void
sighand(int sig)
{
	signum = sig;
}

/*
 * Check an arena for consistency.
 * XXX way too paranoid and can be simplified
 */
static inline void
arena_check(const struct arena *arena, const char *whence)
{
	debug3_f("%s: arena %p: alloc %p cap %zu fo %zu lo %zu act %zu",
	    whence, arena, arena->alloc, arena->capacity, arena->first_offset,
	    arena->last_offset, arena->active_bytes);
	if (arena->last_offset > arena->capacity)
		fatal_f("%s: bad last_offset", whence);
	if (arena->first_offset > arena->capacity ||
	    arena->last_offset > arena->capacity)
		fatal_f("%s: bad offset", whence);
	if (arena->active_bytes > arena->capacity)
		fatal_f("%s: capacity", whence);
	if ((arena->active_bytes == 0) != (arena->active_packets == 0))
		fatal_f("%s: inconsistent active", whence);
}

/*
 * Check a queued packet for internal consistency and consistency with its arena
 * XXX way too paranoid and can be simplified
 */
static inline void
packet_check(const struct arena *arena, const struct packet *packet,
    const char *whence)
{
	debug3_f("%s: packet %p: len %zu id %llu", whence,
	    packet, packet->l, packet->id);
	if ((uintptr_t)packet % PACKET_ALIGN != 0)
		fatal_f("bad align");
	if ((const u_char *)packet < arena->alloc ||
	    (const u_char *)packet > arena->alloc + arena->capacity -
	    sizeof(*packet))
		fatal_f("%s: packet out of bounds", whence);
	if (packet->magic1 != arena->magic1 ||
	    packet->magic2 != arena->magic2)
		fatal_f("%s: bad magic", whence);
	if (packet->l > MAX_PACKET)
		fatal_f("%s: bad len", whence);
	if (packet->d != (const u_char *)packet + sizeof(*packet))
		fatal_f("%s: bad data ptr", whence);
	if (packet->d < arena->alloc ||
	    packet->d > arena->alloc + arena->capacity)
		fatal_f("%s: data out of bounds", whence);
	if (packet->next_offset > arena->capacity)
		fatal_f("%s: bad next", whence);
	if (arena->active_packets == 0)
		fatal_f("%s: no packets", whence);
	if (arena->active_bytes < packet->l)
		fatal_f("%s: active underflow", whence);
}

/* Allocate an arena queue */
static struct arena *
arena_new(size_t capacity)
{
	struct arena *arena;

	arena = xcalloc(1, sizeof(*arena));
	/* Ensure we can fit an entire packet at the end of the queue */
	arena->capacity = capacity + ARENA_RESERVE;
	arena->alloc = xcalloc(1, arena->capacity);
	arena->active_bytes = arena->first_offset = arena->last_offset = 0;
	arena->next_id = arena->active_packets = 0;
	arena->total_bytes = arena->total_packets = 0;
	arena->magic1 = arc4random();
	arena->magic2 = arc4random();
	arena_check(arena, __func__);
	return arena;
}

/* Free an arena queue */
static void
arena_free(struct arena *arena)
{
	arena_check(arena, __func__);
	free(arena->alloc);
	free(arena);
}

/*
 * Get a pointer to the next free packet slot in the arena.
 * packet->l will contain the space available to read data to.
 * Returns NULL if no slots available.
 */
static struct packet *
arena_packet_get(const struct arena *arena)
{
	struct packet *packet;

	arena_check(arena, __func__);
	if (arena->last_offset > arena->first_offset &&
	    arena->last_offset + ARENA_RESERVE >= arena->capacity) {
		debug3_f("unwrap nospace");
		return NULL;
	}
	if (arena->last_offset < arena->first_offset &&
	    arena->last_offset + ARENA_RESERVE >= arena->first_offset) {
		debug3_f("wrap nospace");
		return NULL;
	}
	if (arena->last_offset == arena->first_offset &&
	    arena->active_packets != 0)
		fatal_f("offsets equal but have packets");
	packet = (struct packet *)(arena->alloc + arena->last_offset);
	if ((uintptr_t)packet % PACKET_ALIGN != 0)
		fatal_f("bad align");
	packet->d = (u_char *)packet + sizeof(*packet);
	packet->l = MAX_PACKET;
	packet->next_offset = -1;
	return packet;
}

/*
 * Commit a packet to the queue.
 * It is the caller's responsibility to update packet->l to reflect the data
 * actually read.
 */
static void
arena_packet_commit(struct arena *arena, struct packet *packet)
{
	debug3_f("packet %p", packet);
	arena_check(arena, __func__);
	arena->last_offset += sizeof(*packet) + packet->l;
	if (arena->last_offset % PACKET_ALIGN != 0) {
		arena->last_offset += PACKET_ALIGN -
		    (arena->last_offset % PACKET_ALIGN);
	}
	arena->active_bytes += packet->l;
	arena->active_packets++;

	if (arena->last_offset + ARENA_RESERVE > arena->capacity) {
		debug3_f("wrap");
		arena->last_offset = 0;
	}

	packet->magic1 = arena->magic1;
	packet->magic2 = arena->magic2;
	packet->next_offset = arena->last_offset;
	packet->id = arena->next_id++;
	packet_check(arena, packet, __func__);
}

/*
 * Return a pointer to the first packet in the queue.
 * Returns NULL if no packets enqueued.
 */
static struct packet *
arena_packet_first(const struct arena *arena)
{
	struct packet *packet;

	arena_check(arena, __func__);
	if (arena->active_packets == 0)
		return NULL;
	packet = (struct packet *)(arena->alloc + arena->first_offset);
	packet_check(arena, packet, __func__);
	return packet;
}

/* Remove a packet from the queue. Removals must be done in FIFO order. */
static void
arena_packet_done(struct arena *arena, struct packet *packet)
{
	arena_check(arena, __func__);
	packet_check(arena, packet, __func__);

	if (packet != (struct packet *)(arena->alloc + arena->first_offset))
		fatal_f("done on un-first packet");
	arena->first_offset = packet->next_offset;
	arena->active_packets--;
	arena->active_bytes -= packet->l;
	arena->total_packets++;
	arena->total_bytes += packet->l;
	memset(packet, 0xff, sizeof(*packet));
}

/* Receive a packet from the network and enqueue it */
static int
receive_packet(int fd, const char *dev, struct arena *arena,
    struct timespec *now, const struct timespec *delay)
{
	struct packet *packet;
	char *hex;
	ssize_t r;

	packet = arena_packet_get(arena);
	if ((r = read(fd, packet->d, packet->l)) == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		error_f("%s read: %s", dev, strerror(errno));
		return -1;
	}
	if (r == 0) {
		logit("%s: input closed", dev);
		return -1;
	}
	packet->l = (size_t)r;
	timespecadd(now, delay, &packet->due);
	arena_packet_commit(arena, packet);

	debug2_f("%s: recv len %zu id %llu (%llu active)", dev, packet->l,
	    packet->id, arena->active_packets);
	if (log_level_get() == SYSLOG_LEVEL_DEBUG3) {
		hex = tohex(packet->d, packet->l);
		//debug3_f("%s: packet id %llu: %s", dev, packet->id, hex);
		free(hex);
	}
	return 0;
}

/* Send a packet and dequeue it */
static int
send_packets(int fd, const char *dev, struct arena *arena, struct timespec *now)
{
	struct packet *packet;
	ssize_t r;

	/* NB. this previously used a loop, but that caused read starvation */
	if ((packet = arena_packet_first(arena)) == NULL ||
	    timespeccmp(&packet->due, now, >))
		return 0;

	debug2_f("%s: send len %zu id %llu "
	    "(queue: %llu pkts %zu bytes)", dev, packet->l, packet->id,
	    arena->active_packets, arena->active_bytes);
	if ((r = write(fd, packet->d, packet->l)) == -1) {
		if (errno == EINTR || errno == EAGAIN ||
		    errno == EWOULDBLOCK)
			return 0;
		error_f("%s write: %s", dev, strerror(errno));
		return -1;
	}
	if (r == 0) {
		logit("%s: output closed", dev);
		return -1;
	}
	arena_packet_done(arena, packet);
	return 0;
}

/* Formal struct poll events/revents flags */
static const char *
format_pollev(int events)
{
	if (events == 0)
		return "NONE";
	if ((events & POLLHUP) != 0)
		return "HUP";
	if ((events & POLLERR) != 0)
		return "ERR";
	if ((events & (POLLIN|POLLOUT)) == (POLLIN|POLLOUT))
		return "INOUT";
	if ((events & POLLIN) != 0)
		return "IN";
	if ((events & POLLOUT) != 0)
		return "OUT";
	return "UNKNOWN";
}

/* Main packet queue loop: bidirectionally read, delay and send packets */
static void
mainloop(const char *tundev0, int tun0, const char *tundev1, int tun1,
    u_int delay_ms, u_int stats_interval_secs, size_t capacity)
{
	int i, ret;
	struct pollfd pfd[2];
	sigset_t nsigset, osigset;
	struct packet *packet;
	struct arena *arena[2];
	unsigned long long last_bytes[2], last_packets[2];
	struct timespec timeout, now, delayts, stats;

	debug2_f("start %s fd=%d %s fd=%d delay=%ums capacity=%zu",
	    tundev0, tun0, tundev1, tun1, delay_ms, capacity);

	last_bytes[0] = last_bytes[1] = last_packets[0] = last_packets[1] = 0;
	arena[0] = arena_new(capacity);
	arena[1] = arena_new(capacity);
	ms_to_timespec(&delayts, delay_ms);
	monotime_ts(&now);

	/* Initialise statistics timer */
	ms_to_timespec(&timeout, stats_interval_secs * 1000);
	timespecadd(&now, &timeout, &stats);

	ssh_signal(SIGINT, sighand);
	ssh_signal(SIGTERM, sighand);

	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGINT);
	sigaddset(&nsigset, SIGTERM);
	sigprocmask(SIG_SETMASK, NULL, &osigset);

	for (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, NULL);
		if (signum != 0) {
			logit("Received signal %d; terminating.", (int)signum);
			break;
		}

		memset(pfd, 0, sizeof(pfd));
		pfd[0].fd = tun0;
		pfd[1].fd = tun1;
		/* Only enable reading if we have packet slots available */
		pfd[0].events = arena_packet_get(arena[0]) == NULL ? 0 : POLLIN;
		pfd[1].events = arena_packet_get(arena[1]) == NULL ? 0 : POLLIN;

		/* Prepare poll timeout and arm output if packets are due */
		ptimeout_init(&timeout);
		monotime_ts(&now);
		if ((packet = arena_packet_first(arena[0])) != NULL) {
			ptimeout_deadline_monotime_tsp(&timeout, &packet->due);
			if (timespeccmp(&packet->due, &now, <))
				pfd[1].events |= POLLOUT;
		}
		if ((packet = arena_packet_first(arena[1])) != NULL) {
			ptimeout_deadline_monotime_tsp(&timeout, &packet->due);
			if (timespeccmp(&packet->due, &now, <))
				pfd[0].events |= POLLOUT;
		}
		if (stats_interval_secs != 0)
			ptimeout_deadline_monotime_tsp(&timeout, &stats);

		if (ptimeout_isset(&timeout))
			debug3_f("timeout in %dms", ptimeout_get_ms(&timeout));
		debug3_f("%s: arm %s", tundev0, format_pollev(pfd[0].events));
		debug3_f("%s: arm %s", tundev1, format_pollev(pfd[1].events));

		ret = ppoll(pfd, 2, ptimeout_get_tsp(&timeout), &osigset);
		if (ret == -1 && errno != EINTR)
			fatal_f("ppoll: %s", strerror(errno));
		sigprocmask(SIG_SETMASK, &osigset, NULL);
		if (ret == -1)
			continue;

		debug3_f("%s: rdy %s", tundev0, format_pollev(pfd[0].revents));
		debug3_f("%s: rdy %s", tundev1, format_pollev(pfd[1].revents));

		monotime_ts(&now);
		/* Display stats */
		if (stats_interval_secs != 0 && timespeccmp(&now, &stats, >)) {
			double pps[2], mbps[2], pct[2];

			for (i = 0; i < 2; i++) {
				pps[i] = arena[i]->total_packets -
				    last_packets[i];
				pps[i] /= stats_interval_secs;
				mbps[i] = (arena[i]->total_bytes -
				    last_bytes[i]) * 8;
				mbps[i] /= stats_interval_secs * 1000000;
				pct[i] = arena[i]->active_bytes * 100;
				pct[i] /= arena[i]->capacity;
				last_packets[i] = arena[i]->total_packets;
				last_bytes[i] = arena[i]->total_bytes;
			}
			logit("%s %7.0fpps %10.3fMbps %2.0f%% cap | "
			    "%s %7.0fpps %10.3fMbps %2.0f%% cap ",
			    tundev0, pps[0], mbps[0], pct[0],
			    tundev1, pps[1], mbps[1], pct[1]);
			ms_to_timespec(&timeout, stats_interval_secs * 1000);
			timespecadd(&now, &timeout, &stats);
		}
		/* Handle 1st tun input */
		if ((pfd[0].revents & (POLLIN|POLLHUP)) != 0) {
			if (receive_packet(tun0, tundev0, arena[0],
			    &now, &delayts) == -1)
				break;
		}
		/* Handle 1st tun queue to 2nd tun output */
		if ((pfd[1].revents & POLLOUT) != 0) {
			if (send_packets(tun1, tundev1, arena[0], &now) == -1)
				break;
		}
		/* Handle 2nd tun input */
		if ((pfd[1].revents & (POLLIN|POLLHUP)) != 0) {
			if (receive_packet(tun1, tundev1, arena[1],
			    &now, &delayts) == -1)
				break;
		}
		/* Handle 2nd tun queue to 1st tun output */
		if ((pfd[0].revents & POLLOUT) != 0) {
			if (send_packets(tun0, tundev0, arena[1], &now) == -1)
				break;
		}
	}
	/* Final stats */
	verbose("%s: packets %llu bytes %llu "
	    "(%llu packets / %zu bytes still active)",
	    tundev0, arena[0]->total_bytes, arena[0]->total_packets,
	    arena[0]->active_packets, arena[0]->active_bytes);
	verbose("%s: packets %llu bytes %llu "
	    "(%llu packets / %zu bytes still active)",
	    tundev1, arena[1]->total_bytes, arena[1]->total_packets,
	    arena[1]->active_packets, arena[1]->active_bytes);
	arena_free(arena[0]);
	arena_free(arena[1]);
	sigprocmask(SIG_SETMASK, &osigset, NULL);
	ssh_signal(SIGINT, sighand);
	ssh_signal(SIGTERM, sighand);
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [options] tunN tunN\n", __progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h       Display this help.\n");
	fprintf(stderr, "  -D       Daemonise; put %s into the background.\n", __progname);
	fprintf(stderr, "  -q       Quiet mode; suppress output (may be used more than once).\n");
	fprintf(stderr, "  -v       Verbose mode (may be used more than once).\n");
	fprintf(stderr, "  -P path  Record process ID to file.\n");
	fprintf(stderr, "  -S secs  Report statistics every 'secs' interval (default: 10).\n");
	fprintf(stderr, "  -d ms    Delay traffic for 'ms' milliseconds (default: 0).\n");
	fprintf(stderr, "  -c MB    Specify delay queue capacity in MB (default: 32).\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	int ch;
	extern char *optarg;
	extern int optind;
	const char *errstr;
	u_int delay_ms = 0, capacity_mb = 32, stats_interval_secs = 10;
	int if0, if1, tun0 = -1, tun1 = -1, daemon_flag = 0;
	char *pid_file = NULL, *tundev0 = NULL, *tundev1 = NULL;
	FILE *f = NULL;
	sigset_t sigmask;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, NULL);

	while ((ch = getopt(argc, argv, "DhvqP:c:d:S:")) != -1) {
		switch (ch) {
		case 'D':
			daemon_flag = 1;
			break;
		case 'P':
			pid_file = xstrdup(optarg);
			break;
		case 'v':
			if (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			break;
		case 'q':
			if (log_level > SYSLOG_LEVEL_QUIET)
				log_level--;
			break;
		case 'd':
			delay_ms = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				fatal("invalid -d argument: %s", errstr);
			break;
		case 'c':
			/* 64GB ought to be enough for anyone */
			capacity_mb = strtonum(optarg, 1, 64*1024, &errstr);
			if (errstr != NULL)
				fatal("invalid -c argument: %s", errstr);
			break;
		case 'S':
			stats_interval_secs = strtonum(optarg, 0,
			    INT_MAX / 1000, &errstr);
			if (errstr != NULL)
				fatal("invalid -s argument: %s", errstr);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2)
		usage();

	log_init(__progname, log_level, SYSLOG_FACILITY_USER, 1);

	if (strncmp(argv[0], "tun", 3) != 0)
		fatal("Unrecognised tunnel device name \"%s\"", argv[0]);
	if0 = strtonum(argv[0] + 3, 0, INT_MAX, &errstr);
	if (errstr != NULL)
		fatal("Invalid tunnel device name \"%s\"", argv[0]);
	if (strncmp(argv[1], "tun", 3) != 0)
		fatal("Unrecognised tunnel device name \"%s\"", argv[1]);
	if1 = strtonum(argv[1] + 3, 0, INT_MAX, &errstr);
	if (errstr != NULL)
		fatal("Invalid tunnel device name \"%s\"", argv[1]);
	if (if0 == if1)
		fatal("Both tunnel devices are the same");

	/*
	 * XXX this could be made to work with other network interfaces, e.g
	 * divert(4) sockets.
	 */
	if ((tun0 = tun_open(if0, SSH_TUNMODE_POINTOPOINT, &tundev0)) == -1)
		fatal("failed to open tun%d", if0);
	if ((tun1 = tun_open(if1, SSH_TUNMODE_POINTOPOINT, &tundev1)) == -1)
		fatal("failed to open tun%d", if0);
	set_nonblock(tun0);
	set_nonblock(tun1);

	logit("delaying for %ums between interfaces \"%s\" and \"%s\" with "
	    "capacity %uMB", delay_ms, tundev0, tundev1, capacity_mb);

	if (pid_file != NULL && (f = fopen(pid_file, "w")) == NULL)
		fatal("fopen %s: %s", pid_file, strerror(errno));

	if (daemon_flag)
		daemon(0, log_level >= SYSLOG_LEVEL_DEBUG1);

	if (pid_file != NULL) {
		fprintf(f, "%ld\n", (long)getpid());
		fclose(f);
	}

	mainloop(tundev0, tun0, tundev1, tun1,
	    delay_ms, stats_interval_secs, (size_t)capacity_mb * 1024 * 1024);

	free(tundev0);
	free(tundev1);
	close(tun0);
	close(tun1);

	if (pid_file != NULL)
		unlink(pid_file);

	return 0;
}
