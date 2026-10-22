#!/bin/sh
# Runs the e2e-compose test command and, beside it, does what the test asks
# of the host through files in a handshake directory: the test runs in a
# container with no docker access, and the group scenario stops a group's
# owner task, an rcs-as container of this stack (#121 D4). The docker socket
# is never given to the test.
#
# The test writes, in the handshake directory:
#   stop          an rcs-as task's IPv4 address on the stack's network: the
#                 host stops that container and writes `stopped` with its
#                 service name, or `failed` with why;
#   logs-request  the host writes every rcs-as container's log to `logs`
#                 (atomically, by a rename) and removes the request.
# Whatever the test's outcome, every container stopped for it is started
# again, and waited for until healthy, before this exits; the exit status is
# the test's, or 1 if a container did not come back.
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
# Every docker call is bounded, as is the wait for a restarted container.
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

rm -rf "$dir"
mkdir -p "$dir" || exit 1
stopped=""

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

stop_owner() {
	addr=$(tr -d ' \r\n' <"$dir/stop")
	rm -f "$dir/stop"
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
	# Above RCS_SHUTDOWN_TIMEOUT (20 s), as the compose file's
	# stop_grace_period: a clean stop, whose last beat lets the other task
	# take the groups at once.
	if ! bounded "$docker_timeout" docker stop -t 25 "$name" >/dev/null; then
		echo "docker stop failed" >"$dir/failed"
		return
	fi
	stopped="$stopped $name"
	service "$name" >"$dir/stopped.tmp" && mv "$dir/stopped.tmp" "$dir/stopped"
}

write_logs() {
	rm -f "$dir/logs-request"
	: >"$dir/logs.tmp"
	for name in $(bounded "$docker_timeout" docker ps -a --filter "label=com.docker.compose.project=$project" --format '{{.Names}}'); do
		case "$(service "$name")" in
		rcs-as-*) bounded "$docker_timeout" docker logs "$name" >>"$dir/logs.tmp" 2>&1 ;;
		esac
	done
	mv "$dir/logs.tmp" "$dir/logs"
}

restart_stopped() {
	failed=0
	for name in $stopped; do
		if ! bounded "$docker_timeout" docker start "$name" >/dev/null; then
			echo "e2e-compose: $name did not start again" >&2
			failed=1
			continue
		fi
		waited=0
		until [ "$(bounded "$docker_timeout" docker inspect -f '{{.State.Health.Status}}' "$name")" = healthy ]; do
			if [ "$waited" -ge "$healthy_timeout" ]; then
				echo "e2e-compose: $name is not healthy ${healthy_timeout}s after it started again" >&2
				failed=1
				break
			fi
			sleep 2
			waited=$((waited + 2))
		done
	done
	stopped=""
	return "$failed"
}

"$@" &
test_pid=$!
# Interrupted, the test container goes too, and what was stopped comes back.
trap 'kill "$test_pid" 2>/dev/null; bounded "$docker_timeout" docker rm -f "$container" >/dev/null 2>&1; restart_stopped; exit 130' INT TERM

while kill -0 "$test_pid" 2>/dev/null; do
	[ -f "$dir/stop" ] && stop_owner
	[ -f "$dir/logs-request" ] && write_logs
	sleep 0.2
done
wait "$test_pid"
status=$?
trap - INT TERM
restart_stopped || status=1
exit "$status"
