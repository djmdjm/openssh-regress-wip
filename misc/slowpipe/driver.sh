#!/bin/sh

MAX_MS=500
STEP_MS=20
CAPACITY=1024 # MB
TUN0="tun0"
TUN1="tun1"
RDOMAIN=100
TUN0_ADDR=192.168.0.1
TUN1_ADDR=192.168.1.1
MB=100
TCPBENCH_TIME=20

msg() {
	echo "$@" 1>&2
}

die() {
	echo "$@" 1>&2
	exit 1
}

wait_for_pidfile() {
	WHAT=$1
	PIDPATH=$2

	STARTED=""
	for x in `seq 50 1 `; do
		if test -f $PIDPATH && grep -q '^[0-9]' $PIDPATH ; then
			STARTED=1
			break
		fi
		sleep 0.1
	done
	test -z "$STARTED" && die "$WHAT didn't start"
}

wait_for_exit() {
	WHAT=$1
	WAITPID=$2

	test -z "$WAITPID" && return

	doas kill $WAITPID || true
	for x in `seq 50 1 `; do
		doas kill -0 $WAITPID 2>/dev/null || break
		sleep 0.1
	done
	doas kill -0 $WAITPID 2>/dev/null && die "$WHAT didn't stop"
}

SLOWPIPE_PID=""
SSHD_PID=""
NC_PID=""
TIME_TMP=""
DATA_TMP=""
SSHD_PID_TMP=""
SSH_MUX_TMP=""
SLOWPIPE_PID_TMP=""
TCPBENCH_PID=""
TIME_TMP=`mktemp /tmp/time.XXXXXXXXXX` || die "mktemp failed"
DATA_TMP=`mktemp /tmp/data.XXXXXXXXXX` || die "mktemp failed"
SSHD_PID_TMP=`mktemp /tmp/sshd.XXXXXXXXXX` || die "mktemp failed"
SSH_MUX_TMP=`mktemp -u /tmp/ssh.XXXXXXXXXX` || die "mktemp failed"
SLOWPIPE_PID_TMP=`mktemp /tmp/slowpipe.XXXXXXXXXX` || die "mktemp failed"

tun_setup() {
	# Spurious routes break the test
	doas route delete $TUN1_ADDR >/dev/null 2>&1 || true
	tun_destroy
	doas ifconfig $TUN1 create rdomain 100
	doas ifconfig $TUN0 inet $TUN0_ADDR $TUN1_ADDR
	doas ifconfig $TUN1 inet $TUN1_ADDR $TUN0_ADDR
}

tun_destroy() {
	doas ifconfig $TUN0 destroy >/dev/null 2>&1 || true
	doas ifconfig $TUN1 destroy >/dev/null 2>&1 || true
	doas ifconfig lo100 destroy >/dev/null 2>&1 || true
}

start_slowpipe() {
	DELAY=$1
	doas $PWD/obj/slowpipe -Dq -s0 -P $SLOWPIPE_PID_TMP \
	    -d $DELAY -c $CAPACITY $TUN0 $TUN1 || \
	    die "failed to start slowpipe"
	wait_for_pidfile slowpipe $SLOWPIPE_PID_TMP
	SLOWPIPE_PID=$(cat $SLOWPIPE_PID_TMP)
}

stop_slowpipe() {
	sleep 2 # Let traffic drain
	wait_for_exit slowpipe $SLOWPIPE_PID
	SLOWPIPE_PID=""
}

start_sshd() {
	doas /usr/sbin/sshd -D -oListenAddress="0.0.0.0 rdomain $RDOMAIN" \
	    -oPidFile=$SSHD_PID_TMP &
	SSHD_PID=$!
	wait_for_pidfile sshd $SSHD_PID_TMP
}

stop_sshd() {
	wait_for_exit sshd $SSHD_PID
	SSHD_PID=""
}

start_tcpbench() {
	doas tcpbench -sr0 -V $RDOMAIN >/dev/null 2>&1 &
	TCPBENCH_PID=$!
	sleep 1
}

stop_tcpbench() {
	wait_for_exit tcpbench $TCPBENCH_PID
	TCPBENCH_PID=""
}

cleanup() {
	trap - EXIT INT ERR
	set +e
	stop_sshd
	stop_tcpbench
	stop_slowpipe
	tun_destroy
	if ! test -z "$SSH_MUX_TMP" && test -S "$SSH_MUX_TMP" ; then
		ssh -F none -O exit -oControlPath=$SSH_MUX_TMP $TUN1_ADDR \
			>/dev/null 2>&1
	fi
	test -z "$TIME_TMP" || rm -f $TIME_TMP
	test -z "$SSHD_PID_TMP" || doas rm -f $SSHD_PID_TMP
	test -z "$SLOWPIPE_PID_TMP" || doas rm -f $SLOWPIPE_PID_TMP
	if [ $EXIT_STATUS -ne 0 ] ; then
		test -z "$DATA_TMP" || rm -f $DATA_TMP
	fi
	exit $EXIT_STATUS
}
EXIT_STATUS=1
trap cleanup EXIT INT ERR

# set -x

tun_setup

echo "DELAY,SSH_MBPS,TCP_MBPS" > $DATA_TMP

for delay in `jot - 0 $MAX_MS $STEP_MS` ; do
	msg "Starting for delay ${delay}ms"
	start_slowpipe $delay

	msg "Measuring ssh transfer of ${MB}MB"
	start_sshd
	ssh -F none -nNf -oControlMaster=yes -oControlPath=$SSH_MUX_TMP \
	    -oForkAfterAuthentication=yes $TUN1_ADDR || die "ssh mux failed"
	dd if=/dev/zero bs=1M count=1 2>/dev/null | \
	    ssh -qFnone -oControlPath=$SSH_MUX_TMP -oControlMaster=no \
	    $TUN1_ADDR "cat > /dev/null" || "die ssh prime failed"
	dd if=/dev/zero bs=1M count=$MB 2>/dev/null | \
	    { time -p ssh -qFnone -oControlPath=$SSH_MUX_TMP \
	      -oControlMaster=no $TUN1_ADDR "cat > /dev/null"; } \
	    2> $TIME_TMP || die "ssh xfer failed"
	ssh -F none -O exit -oControlPath=$SSH_MUX_TMP $TUN1_ADDR \
	    >/dev/null 2>&1
	# This is the worst shell artithmetic I have ever written - djm
	real_time=$(grep '^real' $TIME_TMP | awk '{print $2}')
	time_ms=$(echo "$real_time" | sed 's/^[0]*//;s/[.]//;s/$/0/')
	ssh_kbps=$(( ($MB * 8 * 1000 * 1000) / $time_ms ))
	ssh_rate=$(printf "%d.%03d" $(($ssh_kbps / 1000)) $(($ssh_kbps % 1000)) )
	stop_sshd
	msg "ssh transfer of ${MB}MB took ${time_ms}ms at ${ssh_rate}Mbps"

	msg "Measuring TCP throughput for ${TCPBENCH_TIME} seconds"
	start_tcpbench
	tcpbench -r 0 -t${TCPBENCH_TIME} $TUN1_ADDR > $TIME_TMP || \
	    die "tcpbench failed"
	tcp_rate=$(grep '^bandwidth ' $TIME_TMP | cut -d/ -f6)
	[ $? -ne 0 ] && die "missing tcpbench stats"
	msg "TCP rate ${tcp_rate}Mbps"
	msg

	echo ${delay},${ssh_rate},${tcp_rate} >> $DATA_TMP

	stop_tcpbench
	stop_slowpipe
done

EXIT_STATUS=0
msg "results in $DATA_TMP"

cat $DATA_TMP
