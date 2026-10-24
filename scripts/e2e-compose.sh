#!/bin/sh
# Runs the e2e-compose test command and, beside it, does what the test asks
# of the host through files in a handshake directory: the test runs in a
# container with no docker access, and the group scenario stops a group's
# owner task, an rcs-as container of this stack (#121 D4). The docker socket
# is never given to the test.
#
# The test writes, in the handshake directory:
#   stop          an rcs-as task's IPv4 address on the stack's network: the
#                 host stops that container cleanly and writes `stopped`
#                 with its service name, or `failed` with why;
#   kill          the same, killing the container (SIGKILL) as a crash
#                 would: no shutdown, no last heartbeat;
#   restart       the host restarts every rcs-as container of the stack (a
#                 clean stop, which writes the task's counters, then a
#                 start), waits until each is healthy, and writes
#                 `restarted` with the time after, in Unix seconds, or
#                 `failed` with why;
#   logs-request  the host writes every rcs-as container's log to `logs`
#                 (atomically, by a rename) and removes the request. The
#                 request may hold a time in Unix seconds, from which on
#                 the logs are written (docker logs --since).
# Each container is recorded before it is stopped or killed. Whatever the
# test's outcome, every one recorded is started again, and waited for until
# healthy, before this exits, a failure to start one not keeping the others
# from starting; the exit status is the test's, or 1 if a container did not
# come back.
#
# A run starts in a later minute than the last run of this project ended
# in: scscf counts each IMPI's challenges in fixed one-minute windows, 10 at
# most (internal/scscf/registrar), and one run registers each test
# subscriber several times, so two runs in one window can use up the
# budget and fail a REGISTER with 500 (#648). The time the last run ended
# is kept beside the handshake directory, in <handshake dir>-<project>.ended,
# which make down removes with the budget.
#
# usage: scripts/e2e-compose.sh <project> <handshake dir> <container> command...
#   project    the compose project (COMPOSE_PROJECT): its network is
#              <project>_default, and only its rcs-as containers are touched
#   container  the name the test container runs under, removed if this is
#              interrupted
set -u

project=$1 dir=$2 container=$3
shift 3
network="${project}_default"
# Every docker call is bounded, and the wait for a restarted container is
# bounded in wall time, the docker calls in it included.
docker_timeout=60
healthy_timeout=120

# bounded runs a command for at most $1 seconds, then kills it; its status
# is the command's. Not timeout(1), which macOS lacks. The killer's output
# goes nowhere, so that a $(bounded ...) does not wait for its sleep.
bounded() {
	secs=$1
	shift
	"$@" &
	pid=$!
	(
		sleep "$secs"
		kill "$pid" 2>/dev/null
	) >/dev/null 2>&1 &
	killer=$!
	wait "$pid"
	rc=$?
	kill "$killer" 2>/dev/null
	wait "$killer" 2>/dev/null
	return "$rc"
}

# wait_challenge_window sleeps until the minute after the one the last run
# of this project ended in, if it is still that minute.
challenge_window=60
ended="${dir%/}-$project.ended"
wait_challenge_window() {
	last=$(cat "$ended" 2>/dev/null) || return 0
	case "$last" in
	*[!0-9]* | "") return 0 ;;
	esac
	next=$(((last / challenge_window + 1) * challenge_window))
	now=$(date +%s)
	if [ "$now" -lt "$next" ]; then
		echo "e2e-compose: the last run ended in this minute; waiting $((next - now)) s for scscf's next challenge window (#648)" >&2
		sleep $((next - now))
	fi
}

# mark_ended records when this run ended.
mark_ended() {
	date +%s >"$ended"
}

rm -rf "$dir"
mkdir -p "$dir" || exit 1
stopped=""
wait_challenge_window

# rcsas_container prints the name of the rcs-as container of this project
# with the IPv4 address $1 on its network, if there is one.
rcsas_container() {
	bounded "$docker_timeout" docker network inspect "$network" \
		-f '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}' |
		while read -r name addr; do
			[ "${addr%/*}" = "$1" ] || continue
			svc=$(bounded "$docker_timeout" docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}} {{index .Config.Labels "com.docker.compose.project"}}' "$name") || continue
			case "$svc" in
			"rcs-as-"*" $project") echo "$name" ;;
			esac
		done
}

# service prints a container's compose service.
service() {
	bounded "$docker_timeout" docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$1"
}

# remember records container $1 among those to start again, once.
remember() {
	case " $stopped " in
	*" $1 "*) ;;
	*) stopped="$stopped $1" ;;
	esac
}

# forget takes container $1 out of those to start again.
forget() {
	kept=""
	for n in $stopped; do
		[ "$n" = "$1" ] || kept="$kept $n"
	done
	stopped=$kept
}

# stop_owner acts on the request file $1, stop or kill: it stops the rcs-as
# container with the address the file holds, cleanly or by SIGKILL.
stop_owner() {
	kind=$1
	addr=$(tr -d ' \r\n' <"$dir/$kind")
	rm -f "$dir/$kind"
	case "$addr" in
	*[!0-9.]* | "")
		echo "not an IPv4 address" >"$dir/failed"
		return
		;;
	esac
	name=$(rcsas_container "$addr")
	if [ -z "$name" ]; then
		echo "no rcs-as container of $project has that address" >"$dir/failed"
		return
	fi
	# Recorded first: a stop cut short by its bound may still have stopped
	# it, and it must come back either way.
	remember "$name"
	if [ "$kind" = kill ]; then
		bounded "$docker_timeout" docker kill "$name" >/dev/null
	else
		# Above RCS_SHUTDOWN_TIMEOUT (20 s), as the compose file's
		# stop_grace_period: a clean stop, whose last beat lets the other
		# task take the groups soon.
		bounded "$docker_timeout" docker stop -t 25 "$name" >/dev/null
	fi || {
		echo "docker $kind failed" >"$dir/failed"
		return
	}
	service "$name" >"$dir/stopped.tmp" && mv "$dir/stopped.tmp" "$dir/stopped"
}

# rcsas_containers prints the names of this project's rcs-as containers.
rcsas_containers() {
	for name in $(bounded "$docker_timeout" docker ps -a --filter "label=com.docker.compose.project=$project" --format '{{.Names}}'); do
		case "$(service "$name")" in
		rcs-as-*) echo "$name" ;;
		esac
	done
}

write_logs() {
	since=$(tr -d ' \r\n' <"$dir/logs-request")
	rm -f "$dir/logs-request"
	case "$since" in
	*[!0-9]*) since="" ;;
	esac
	: >"$dir/logs.tmp"
	for name in $(rcsas_containers); do
		if [ -n "$since" ]; then
			bounded "$docker_timeout" docker logs --since "$since" "$name" >>"$dir/logs.tmp" 2>&1
		else
			bounded "$docker_timeout" docker logs "$name" >>"$dir/logs.tmp" 2>&1
		fi
	done
	mv "$dir/logs.tmp" "$dir/logs"
}

# start_healthy starts container $1 and waits until it is healthy, for at
# most healthy_timeout seconds of wall time.
start_healthy() {
	if ! bounded "$docker_timeout" docker start "$1" >/dev/null; then
		echo "e2e-compose: $1 did not start again" >&2
		return 1
	fi
	began=$(date +%s)
	until [ "$(bounded "$docker_timeout" docker inspect -f '{{.State.Health.Status}}' "$1")" = healthy ]; do
		if [ $(($(date +%s) - began)) -ge "$healthy_timeout" ]; then
			echo "e2e-compose: $1 is not healthy ${healthy_timeout}s after it started again" >&2
			return 1
		fi
		sleep 2
	done
}

# restart_stopped starts every container recorded, each whatever became of
# the others, and keeps those that did not come back recorded.
restart_stopped() {
	failed=0
	for name in $stopped; do
		if start_healthy "$name"; then
			forget "$name"
		else
			failed=1
		fi
	done
	return "$failed"
}

# restart_all restarts every rcs-as container, so that each writes its
# counters as it stops and starts with none: the logs from the time it
# writes then on hold one run's counters alone. Each is recorded before it
# is stopped, so that one that does not come back is started again at the
# end too.
restart_all() {
	rm -f "$dir/restart" "$dir/restarted"
	why=""
	for name in $(rcsas_containers); do
		remember "$name"
		bounded "$docker_timeout" docker stop -t 25 "$name" >/dev/null || why="docker stop failed"
	done
	restart_stopped || why="an rcs-as task did not come back"
	if [ -n "$why" ]; then
		echo "$why" >"$dir/failed"
		return
	fi
	date +%s >"$dir/restarted.tmp" && mv "$dir/restarted.tmp" "$dir/restarted"
}

"$@" &
test_pid=$!
# Interrupted, the test container goes too, and what was stopped comes back.
trap 'kill "$test_pid" 2>/dev/null; bounded "$docker_timeout" docker rm -f "$container" >/dev/null 2>&1; mark_ended; restart_stopped; exit 130' INT TERM

while kill -0 "$test_pid" 2>/dev/null; do
	[ -f "$dir/stop" ] && stop_owner stop
	[ -f "$dir/kill" ] && stop_owner kill
	[ -f "$dir/restart" ] && restart_all
	[ -f "$dir/logs-request" ] && write_logs
	sleep 0.2
done
wait "$test_pid"
status=$?
mark_ended
trap - INT TERM
restart_stopped || status=1
exit "$status"
