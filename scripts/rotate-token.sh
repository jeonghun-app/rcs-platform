#!/usr/bin/env bash
#
# Rotates one internal token of a stack (ADR 0007 §4, docs/runbook.md#token-rotation).
#
# Each token has two secrets, <stack>/<token> (current) and
# <stack>/<token>-next. The receiver accepts both; the caller presents the
# current one. Tasks read secrets when they start, so every step ends with a
# rolling restart, and the next step starts only once the restarted service
# is steady: one deployment, completed, all tasks running. Any failure stops
# the rotation where it is. Every step reads where the rotation stands before
# it writes (each secret's current and previous version), so running a step
# again, after a failed restart say, never undoes a write: it finishes what
# is missing and restarts again.
#
#   1. a new value goes into next; the receiver restarts and accepts old and new;
#   2. old goes into next, then new into current; the receiver restarts (so
#      no task that started between the two writes keeps a wrong pair), then
#      the caller restarts and presents new;
#   3. a fresh, unused value replaces old in next; the receiver restarts and
#      no longer accepts old.
#
# Values pass through shell variables and, for a moment, a file only the
# user can read; they never reach the screen or a command line.
#
# This changes secrets and restarts services: run it only with the approval
# docs/aws-deployment.md asks for.

set -euo pipefail

STACK="rcs-platform"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
TOKEN=""
STEP="all"
# How long one restart may take: ft-server's 300 s deregistration delay and
# 100 s drain per task make its rollouts long.
WAIT_SECONDS="${ROTATE_WAIT_SECONDS:-2700}"
POLL_SECONDS="${ROTATE_POLL_SECONDS:-15}"

usage() {
  cat <<'USAGE'
Usage: scripts/rotate-token.sh --token NAME [options]

  --token NAME        hss/admin-token, hss/ft-server-token, hss/acs-token or
                      msrp-relay/pcscf-token
  --stack-name NAME   Default rcs-platform
  --region REGION     Default $AWS_REGION, $AWS_DEFAULT_REGION or ap-northeast-2
  --step 1|2|3|all    Run one step, or all (default). A token whose caller
                      is not a service of the stack stops after step 2: give
                      callers the new current value, then run --step 3.
  -h, --help          Show this help
USAGE
}

fail() {
  echo "rotate-token.sh: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --token | --stack-name | --region | --step)
      [[ $# -ge 2 ]] || fail "$1 needs a value"
      case "$1" in
        --token) TOKEN="$2" ;;
        --stack-name) STACK="$2" ;;
        --region) REGION="$2" ;;
        --step) STEP="$2" ;;
      esac
      shift 2
      ;;
    -h | --help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

# Who receives and who presents each token. "" is a caller outside the stack:
# the operator, or a service not deployed or not wired yet.
case "$TOKEN" in
  hss/admin-token) RECEIVER=hss CALLER="" ;;
  hss/ft-server-token) RECEIVER=hss CALLER=ft-server ;;
  hss/acs-token) RECEIVER=hss CALLER="" ;;
  msrp-relay/pcscf-token) RECEIVER=msrp-relay CALLER="" ;;
  "") fail "--token is required" ;;
  *) fail "unknown token: $TOKEN" ;;
esac
case "$STEP" in 1 | 2 | 3 | all) ;; *) fail "--step must be 1, 2, 3 or all" ;; esac
[[ "$STACK" =~ ^[a-z][a-z0-9-]{0,39}$ ]] || fail "not a stack name of deploy.sh: $STACK"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"

get() {
  local value
  value="$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$STACK/$1" \
    --query SecretString --output text)"
  [[ -n "$value" && "$value" != None ]] || fail "$STACK/$1 is empty"
  printf '%s' "$value"
}

# The value a secret held before its last write (its AWSPREVIOUS version),
# or nothing when it was written once.
previous() {
  local value
  if value="$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$STACK/$1" \
    --version-stage AWSPREVIOUS --query SecretString --output text 2>/dev/null)"; then
    [[ "$value" == None ]] || printf '%s' "$value"
  fi
}

# Where the rotation stands, from both secrets' current and previous values:
#   swapped  step 2 wrote both (current = new, next = old);
#   half     step 2 wrote next only (both hold old, next's previous is new);
#   retired  step 3 wrote next (both secrets' previous is old);
#   ready    anything else with two different values: steps 1 or 2 may run.
rotation_state() {
  local cur nxt cur_prev nxt_prev
  cur="$(get "$TOKEN")"
  nxt="$(get "$TOKEN-next")"
  cur_prev="$(previous "$TOKEN")"
  nxt_prev="$(previous "$TOKEN-next")"
  if [[ "$cur" != "$nxt" && "$cur_prev" == "$nxt" && "$nxt_prev" == "$cur" ]]; then
    echo swapped
  elif [[ "$cur" == "$nxt" && -n "$nxt_prev" && "$nxt_prev" != "$cur" ]]; then
    echo half
  elif [[ "$cur" != "$nxt" && -n "$cur_prev" && "$cur_prev" == "$nxt_prev" && "$nxt" != "$cur_prev" ]]; then
    echo retired
  elif [[ "$cur" != "$nxt" ]]; then
    echo ready
  else
    echo equal
  fi
}

put() {
  local file="$WORK/value"
  [[ -n "$2" ]] || fail "refusing to store an empty value in $STACK/$1"
  (umask 077 && printf '%s' "$2" >"$file")
  aws secretsmanager put-secret-value --region "$REGION" --secret-id "$STACK/$1" \
    --secret-string "file://$file" >/dev/null
  rm -f "$file"
}

random_value() {
  local value
  value="$(aws secretsmanager get-random-password --region "$REGION" --password-length 64 \
    --exclude-punctuation --query RandomPassword --output text)"
  [[ ${#value} -eq 64 ]] || fail "Secrets Manager returned no usable random value"
  printf '%s' "$value"
}

# Restarts a service and waits until it is steady: one deployment, its
# rollout completed, as many tasks running as desired.
restart() {
  local service="$1" deadline state
  echo "  restarting $service"
  aws ecs update-service --region "$REGION" --cluster "$STACK" --service "$service" \
    --force-new-deployment >/dev/null
  deadline=$((SECONDS + WAIT_SECONDS))
  while :; do
    state="$(aws ecs describe-services --region "$REGION" --cluster "$STACK" --services "$service" \
      --query 'services[0].[length(deployments), deployments[0].rolloutState, runningCount, desiredCount]' \
      --output text)"
    read -r count rollout running desired <<<"$state"
    if [[ "$rollout" == FAILED ]]; then
      fail "$service: the deployment failed (the circuit breaker rolls it back); the rotation stops here"
    fi
    if [[ "$count" == 1 && "$rollout" == COMPLETED && "$running" == "$desired" ]]; then
      echo "  $service steady: $running of $desired tasks"
      return 0
    fi
    [[ $SECONDS -lt $deadline ]] || fail "$service is not steady after $WAIT_SECONDS s ($state); the rotation stops here"
    sleep "$POLL_SECONDS"
  done
}

step1() {
  echo "[1/3] new value into $TOKEN-next"
  case "$(rotation_state)" in
    swapped) fail "step 2 already ran: next holds the old value callers may still present; continue with --step 2 (restarts only) or --step 3" ;;
    half) fail "step 2 stopped between its writes; finish it with --step 2" ;;
  esac
  put "$TOKEN-next" "$(random_value)"
  restart "$RECEIVER"
}

step2() {
  local old new
  echo "[2/3] new value into $TOKEN, old into $TOKEN-next"
  case "$(rotation_state)" in
    swapped) echo "  the writes are done already; restarting only" ;;
    half)
      echo "  finishing the writes: the new value into $TOKEN"
      put "$TOKEN" "$(previous "$TOKEN-next")"
      ;;
    ready | retired)
      old="$(get "$TOKEN")"
      new="$(get "$TOKEN-next")"
      put "$TOKEN-next" "$old"
      put "$TOKEN" "$new"
      unset old new
      ;;
    *) fail "$TOKEN and $TOKEN-next hold the same value: run step 1 first" ;;
  esac
  restart "$RECEIVER"
  if [[ -n "$CALLER" ]]; then
    restart "$CALLER"
  else
    echo "  the callers of $TOKEN are outside this stack: give them the value of $STACK/$TOKEN now,"
    echo "  then run: scripts/rotate-token.sh --stack-name $STACK --region $REGION --token $TOKEN --step 3"
  fi
}

step3() {
  echo "[3/3] a fresh value into $TOKEN-next; old is no longer accepted"
  case "$(rotation_state)" in
    swapped) put "$TOKEN-next" "$(random_value)" ;;
    retired) echo "  the write is done already; restarting only" ;;
    *) fail "step 2 has not run: next may hold the value callers are switching to; run --step 2 first" ;;
  esac
  restart "$RECEIVER"
}

echo "stack $STACK, region $REGION, token $TOKEN (receiver $RECEIVER, caller ${CALLER:-outside the stack})"
case "$STEP" in
  1) step1 ;;
  2) step2 ;;
  3) step3 ;;
  all)
    step1
    step2
    [[ -n "$CALLER" ]] || exit 0
    step3
    ;;
esac
echo "done"
