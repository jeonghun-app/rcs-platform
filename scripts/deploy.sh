#!/usr/bin/env bash
#
# Deploys the RCS platform to AWS in one command (ADR 0003,
# docs/aws-deployment.md):
#
#   1. the registry stack, infra/ecr.yaml: the image repositories and the
#      bucket the platform template is uploaded to;
#   2. the platform image (`make image`), pushed under an immutable tag, and
#      the pinned acs release image (ADR 0006), copied from GHCR by digest;
#      neither is pushed when ECR already holds its tag;
#   3. the platform stack, infra/platform.yaml, with every parameter taken from
#      the config file. Nothing falls back to a template default or to the
#      previous value, so a rollback deploys exactly what its command says.
#
# Each stack change goes through a change set: deploy.sh prints what it would
# add, change, replace and remove, and runs it only after the stack name is
# typed (or with --yes). --plan stops after printing.
#
# This writes to the AWS account the credentials point at. Run it only with
# the approval docs/aws-deployment.md asks for. --dry-run checks the config
# and prints the commands without calling AWS or Docker.

set -euo pipefail

# The acs release this commit deploys (ADR 0006): acs's own release image,
# pinned by the digest of its index, so ECR gets the same bytes the local
# stack runs (the Makefile's ACS_VERSION and ACS_DIGEST; a test keeps them
# equal). Raise both together, in their own pull request, after reading
# acs's CHANGELOG.
ACS_VERSION="1.4.0"
ACS_DIGEST="sha256:00956e9fe4d5865cf5e39292122ec1df78e34993f5c9d07928fff836af5f33b2"
ACS_SOURCE="ghcr.io/jeonghun-app/auto-configuration-server"

# The registry stack's settings. They are constants rather than options so
# that every deployment passes the same values.
UNTAGGED_IMAGE_EXPIRY_DAYS=7
MAX_TAGGED_IMAGES=30

# Fargate On-Demand vCPU, the quota a rolling update must fit in.
FARGATE_VCPU_QUOTA="L-3032A538"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORM_TEMPLATE="$ROOT/infra/platform.yaml"
ECR_TEMPLATE="$ROOT/infra/ecr.yaml"

# Platform parameters this script sets itself; the config file may not.
MANAGED_PARAMETERS=(EcrStackName ImageTag ImageDigest AcsImageTag AcsImageDigest
  S3PrefixListId DynamoDbPrefixListId TemplateRevision PreviousImageTag DeployPrincipalArn)

CONFIG=""
STACK="rcs-platform"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
IMAGE_TAG=""
ACS_IMAGE_TAG=""
SKIP_BUILD=false
DRY_RUN=false
PLAN=false
YES=false

usage() {
  cat <<'USAGE'
Usage: scripts/deploy.sh --config FILE [options]

  --config FILE         Platform parameters, one Key=Value per line, every
                        parameter of infra/platform.yaml except those this
                        script sets (see infra/platform.example.params)
  --stack-name NAME     Platform stack (default rcs-platform). The registry
                        stack is NAME-ecr, its repositories NAME and NAME-acs.
  --region REGION       Default $AWS_REGION, $AWS_DEFAULT_REGION or ap-northeast-2
  --skip-build          Build and push nothing: deploy images already in ECR.
                        Needs --image-tag. This is the rollback.
  --image-tag TAG       Platform image to deploy; only with --skip-build.
                        Without it the tag is `git describe` of a clean tree.
  --acs-image-tag TAG   acs image to deploy; only with --skip-build. Default
                        the pinned ACS_VERSION, copied from GHCR by digest.
  --plan                Build, push and create the change sets, print them,
                        and stop without changing a stack
  --yes                 Run the change sets without asking (CI)
  --dry-run             Check the config and print the commands, calling
                        neither AWS nor Docker
  -h, --help            Show this help
USAGE
}

fail() {
  echo "deploy.sh: $*" >&2
  exit 1
}

usage_error() {
  echo "deploy.sh: $*" >&2
  echo "Run scripts/deploy.sh --help for the options." >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config | --stack-name | --region | --image-tag | --acs-image-tag)
      [[ $# -ge 2 ]] || usage_error "$1 needs a value"
      case "$1" in
        --config) CONFIG="$2" ;;
        --stack-name) STACK="$2" ;;
        --region) REGION="$2" ;;
        --image-tag) IMAGE_TAG="$2" ;;
        --acs-image-tag) ACS_IMAGE_TAG="$2" ;;
      esac
      shift 2
      ;;
    --skip-build) SKIP_BUILD=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --plan) PLAN=true; shift ;;
    --yes) YES=true; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage_error "unknown option: $1" ;;
  esac
done

[[ -n "$CONFIG" ]] || usage_error "--config is required"
[[ -f "$CONFIG" ]] || usage_error "no such config file: $CONFIG"
# Lower case because ECR repository names are; short enough that every name
# derived from it stays within its service's limit.
[[ "$STACK" =~ ^[a-z][a-z0-9-]{0,39}$ ]] ||
  usage_error "--stack-name must be lower-case letters, digits and -, at most 40, starting with a letter"
[[ "$REGION" =~ ^[a-z]{2}(-[a-z]+)+-[0-9]$ ]] || usage_error "not a region: $REGION"
if [[ "$SKIP_BUILD" == true ]]; then
  [[ -n "$IMAGE_TAG" ]] || usage_error "--skip-build needs --image-tag: name the image to deploy"
else
  # A built image is always tagged with the commit it was built from, so a
  # tag in ECR always says what is inside it.
  [[ -z "$IMAGE_TAG$ACS_IMAGE_TAG" ]] ||
    usage_error "--image-tag and --acs-image-tag name images already in ECR; use them with --skip-build"
fi

valid_tag() {
  [[ "$1" =~ ^[0-9A-Za-z_][0-9A-Za-z._-]{0,127}$ ]]
}

# ------------------------------------------------------------------ config

# The parameter names of a template: the keys directly under Parameters.
template_parameters() {
  awk '/^Parameters:/ { p = 1; next }
       p && /^[^[:space:]#]/ { p = 0 }
       p && /^  [A-Za-z0-9]+:[[:space:]]*$/ { sub(/:.*/, ""); print $1 }' "$1"
}

is_managed() {
  local name
  for name in "${MANAGED_PARAMETERS[@]}"; do
    [[ "$name" == "$1" ]] && return 0
  done
  return 1
}

is_parameter() {
  local name
  for name in "${PARAMETERS[@]}"; do
    [[ "$name" == "$1" ]] && return 0
  done
  return 1
}

PARAMETERS=()
while IFS= read -r name; do
  PARAMETERS+=("$name")
done < <(template_parameters "$PLATFORM_TEMPLATE")
[[ ${#PARAMETERS[@]} -gt 0 ]] || fail "found no parameters in $PLATFORM_TEMPLATE"

# Parallel arrays rather than an associative one: macOS ships bash 3.2.
CONFIG_KEYS=()
CONFIG_VALUES=()
PROBLEMS=()

config_index() {
  local i
  for ((i = 0; i < ${#CONFIG_KEYS[@]}; i++)); do
    if [[ "${CONFIG_KEYS[$i]}" == "$1" ]]; then
      echo "$i"
      return 0
    fi
  done
  return 1
}

config_value() {
  local i
  i="$(config_index "$1")" || return 1
  echo "${CONFIG_VALUES[$i]}"
}

number=0
while IFS= read -r line || [[ -n "$line" ]]; do
  number=$((number + 1))
  line="${line%$'\r'}"
  [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
  if [[ ! "$line" =~ ^([A-Za-z0-9]+)=(.*)$ ]]; then
    PROBLEMS+=("line $number: expected Key=Value")
    continue
  fi
  key="${BASH_REMATCH[1]}"
  value="${BASH_REMATCH[2]}"
  # The file is never run by a shell: values are taken literally, and quotes,
  # spaces around a value or a trailing comment are a mistake.
  case "$value" in
    \"* | \'* | [[:space:]]* | *[[:space:]])
      PROBLEMS+=("line $number: $key: values are literal; remove the quotes or the spaces around it")
      continue
      ;;
    *[[:space:]]\#*)
      PROBLEMS+=("line $number: $key: comments go on their own line, not after a value")
      continue
      ;;
  esac
  if is_managed "$key"; then
    PROBLEMS+=("line $number: $key is set by deploy.sh, not by the config")
  elif ! is_parameter "$key"; then
    PROBLEMS+=("line $number: $key is not a parameter of infra/platform.yaml")
  elif config_index "$key" >/dev/null; then
    PROBLEMS+=("line $number: $key is set twice")
  else
    CONFIG_KEYS+=("$key")
    CONFIG_VALUES+=("$value")
  fi
done <"$CONFIG"

for name in "${PARAMETERS[@]}"; do
  if ! is_managed "$name" && ! config_index "$name" >/dev/null; then
    PROBLEMS+=("$name is missing: every parameter is passed explicitly (write $name= for empty)")
  fi
done

if [[ ${#PROBLEMS[@]} -gt 0 ]]; then
  echo "deploy.sh: $CONFIG:" >&2
  printf '  %s\n' "${PROBLEMS[@]}" >&2
  exit 2
fi

# ------------------------------------------------------------- the source

if [[ "$DRY_RUN" == false ]]; then
  command -v aws >/dev/null || fail "the aws CLI is not installed"
  command -v git >/dev/null || fail "git is not installed"
  if [[ "$SKIP_BUILD" == false ]]; then
    for tool in docker make; do
      command -v "$tool" >/dev/null || fail "$tool is not installed"
    done
    docker buildx version >/dev/null 2>&1 || fail "docker buildx is not installed (it copies the acs image)"
  fi
fi

# Every deployment ships the template of the checkout, rollbacks included,
# so it must be a commit: an uncommitted or untracked file could change what
# is deployed without any record of it.
[[ -z "$(git -C "$ROOT" status --porcelain)" ]] ||
  fail "the working tree has uncommitted or untracked files: commit them first, so the deployment names what it ships"
TEMPLATE_REVISION="$(git -C "$ROOT" describe --tags --always)"
[[ "$SKIP_BUILD" == true ]] || IMAGE_TAG="$TEMPLATE_REVISION"
ACS_IMAGE_TAG="${ACS_IMAGE_TAG:-$ACS_VERSION}"
valid_tag "$IMAGE_TAG" || usage_error "not an image tag: $IMAGE_TAG"
valid_tag "$ACS_IMAGE_TAG" || usage_error "not an image tag: $ACS_IMAGE_TAG"

ECR_STACK="$STACK-ecr"
# Constant per stack, so they never change a resource: rcs:stack tells
# stacks sharing an account apart in billing and in the console.
TAG_ARGS=("Key=Application,Value=rcs-platform" "Key=rcs:stack,Value=$STACK")

# ---------------------------------------------------------------- helpers

# Runs a command, or prints it under --dry-run.
run() {
  if [[ "$DRY_RUN" == true ]]; then
    printf '+'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

WORK=""
cleanup() {
  if [[ -n "$WORK" ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
WORK="$(mktemp -d)"

# The status of a stack, or nothing when it does not exist.
stack_status() {
  local out
  if out="$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$1" \
    --query 'Stacks[0].StackStatus' --output text 2>&1)"; then
    echo "$out"
  elif [[ "$out" == *"does not exist"* ]]; then
    echo ""
  else
    fail "cannot read stack $1: $out"
  fi
}

# Refuses a stack that CloudFormation cannot update as it stands. A stack in
# REVIEW_IN_PROGRESS is the empty shell a first change set left behind (an
# interrupted or --plan run): it is created afresh.
check_updatable() {
  local status
  [[ "$DRY_RUN" == true ]] && return 0
  status="$(stack_status "$1")"
  case "$status" in
    "" | REVIEW_IN_PROGRESS | CREATE_COMPLETE | UPDATE_COMPLETE | UPDATE_ROLLBACK_COMPLETE | IMPORT_COMPLETE | IMPORT_ROLLBACK_COMPLETE) ;;
    ROLLBACK_COMPLETE)
      fail "stack $1 is ROLLBACK_COMPLETE: its creation failed and it cannot be updated. Read its events, then delete it (scripts/teardown.sh) and deploy again (docs/runbook.md#first-deployment-rolled-back)" ;;
    *_IN_PROGRESS)
      fail "stack $1 is $status: wait for it to finish" ;;
    *)
      fail "stack $1 is $status: resolve that first (docs/runbook.md#rollback)" ;;
  esac
}

# Whether a stack exists with resources (not absent, not an empty review).
stack_exists() {
  local status
  status="$(stack_status "$1")"
  [[ -n "$status" && "$status" != REVIEW_IN_PROGRESS ]]
}

stack_output() {
  if [[ "$DRY_RUN" == true ]]; then
    echo "<$1:$2>"
    return 0
  fi
  local value
  value="$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$1" \
    --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text)"
  [[ -n "$value" && "$value" != None ]] || fail "stack $1 has no output $2"
  echo "$value"
}

# An output of a stack that may not have it yet; nothing when absent.
optional_output() {
  local value
  value="$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$1" \
    --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text)"
  [[ "$value" == None ]] && value=""
  echo "$value"
}

# Sets DIGEST to the digest ECR holds under the tag, or to nothing. Any error
# but "not found" stops the deployment. (A global, not output: fail must exit
# the script, not a command substitution's subshell.)
DIGEST=""
lookup_digest() {
  local repository="${1#*/}" out
  DIGEST=""
  if out="$(aws ecr describe-images --region "$REGION" --repository-name "$repository" \
    --image-ids "imageTag=$2" --query 'imageDetails[0].imageDigest' --output text 2>&1)"; then
    DIGEST="$out"
  elif [[ "$out" != *ImageNotFoundException* ]]; then
    fail "cannot read repository $repository: $out"
  fi
}

# Whether ECR holds the tag; DIGEST is then its digest.
image_exists() {
  local repository="${1#*/}"
  if [[ "$DRY_RUN" == true ]]; then
    run aws ecr describe-images --region "$REGION" --repository-name "$repository" --image-ids "imageTag=$2"
    DIGEST="<digest of $2>"
    # Show the whole plan: as if the image had to be built, unless the
    # deployment builds nothing.
    if [[ "$SKIP_BUILD" == true ]]; then
      echo "  (dry run: assuming ECR holds it)"
      return 0
    fi
    echo "  (dry run: assuming ECR does not hold it)"
    return 1
  fi
  lookup_digest "$1" "$2"
  [[ -n "$DIGEST" ]]
}

LOGGED_IN=false
registry_login() {
  [[ "$LOGGED_IN" == true ]] && return 0
  if [[ "$DRY_RUN" == true ]]; then
    echo "+ aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin ${1%%/*}"
  else
    aws ecr get-login-password --region "$REGION" |
      docker login --username AWS --password-stdin "${1%%/*}" >/dev/null
  fi
  LOGGED_IN=true
}

# Fargate runs X86_64 (the task definitions say so), whatever the build host is.
build_platform() {
  registry_login "$1"
  run env DOCKER_DEFAULT_PLATFORM=linux/amd64 make -C "$ROOT" image IMAGE="$1" VERSION="$IMAGE_TAG"
  run docker push "$1:$IMAGE_TAG"
  [[ "$DRY_RUN" == true ]] && return 0
  lookup_digest "$1" "$IMAGE_TAG"
  [[ -n "$DIGEST" ]] || fail "ECR does not show $1:$IMAGE_TAG after the push"
}

# Copies the release's index, every platform and attestation in it, byte for
# byte: ECR's digest must then be the pinned one. ECR does not expire images
# an index refers to while the index exists.
copy_acs() {
  registry_login "$1"
  run docker buildx imagetools create --tag "$1:$ACS_IMAGE_TAG" "$ACS_SOURCE@$ACS_DIGEST"
  [[ "$DRY_RUN" == true ]] && return 0
  lookup_digest "$1" "$ACS_IMAGE_TAG"
  [[ "$DIGEST" == "$ACS_DIGEST" ]] ||
    fail "ECR holds ${DIGEST:-nothing} under $1:$ACS_IMAGE_TAG after the copy, not $ACS_DIGEST; delete that image before trying again"
}

# A JSON string of a config value: backslash and quote escaped. Values hold
# no control characters (one line each, and tabs are refused here).
json_string() {
  case "$1" in
    *$'\t'*) fail "a parameter value contains a tab" ;;
  esac
  local s="${1//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '"%s"' "$s"
}

# Writes CloudFormation's --parameters JSON for "Key=Value" arguments.
parameters_file() {
  local file="$1" pair first=true
  shift
  {
    printf '['
    for pair in "$@"; do
      [[ "$first" == true ]] || printf ','
      first=false
      printf '{"ParameterKey":%s,"ParameterValue":%s}' "$(json_string "${pair%%=*}")" "$(json_string "${pair#*=}")"
    done
    printf ']\n'
  } >"$file"
}

# Creates a change set, prints what it changes, and runs it after the stack
# name is typed (or --yes); --plan stops after printing. Arguments: stack,
# then the template option (--template-body file://... or --template-url
# ...), then the parameter pairs.
apply_change_set() {
  local stack="$1" template_option="$2" template="$3" type name reason changes token page replace=0 remove=0 answer
  shift 3
  parameters_file "$WORK/$stack.parameters.json" "$@"
  name="deploy-$(date -u +%Y%m%d%H%M%S)"
  type=UPDATE
  if [[ "$DRY_RUN" == true ]]; then
    type="<CREATE or UPDATE>"
  elif ! stack_exists "$stack"; then
    type=CREATE
  fi
  local create=(aws cloudformation create-change-set --region "$REGION" --stack-name "$stack"
    --change-set-name "$name" --change-set-type "$type" "$template_option" "$template"
    --parameters "file://$WORK/$stack.parameters.json" --capabilities CAPABILITY_IAM --tags "${TAG_ARGS[@]}")
  if [[ "$DRY_RUN" == true ]]; then
    run "${create[@]}"
    echo "  parameters:"
    printf '    %s\n' "$@"
    echo "+ (describe the change set, ask for the stack name, execute it and wait)"
    return 0
  fi
  "${create[@]}" >/dev/null
  if ! aws cloudformation wait change-set-create-complete --region "$REGION" --stack-name "$stack" --change-set-name "$name" 2>/dev/null; then
    reason="$(aws cloudformation describe-change-set --region "$REGION" --stack-name "$stack" --change-set-name "$name" \
      --query StatusReason --output text)"
    aws cloudformation delete-change-set --region "$REGION" --stack-name "$stack" --change-set-name "$name" >/dev/null || true
    case "$reason" in
      *"didn't contain changes"* | *"No updates are to be performed"*)
        echo "  no changes"
        return 0
        ;;
    esac
    fail "the change set for $stack failed: $reason"
  fi

  echo "  changes ($type):"
  token=""
  while :; do
    if [[ -n "$token" ]]; then
      page="$(aws cloudformation describe-change-set --region "$REGION" --stack-name "$stack" --change-set-name "$name" \
        --next-token "$token" --query 'Changes[].ResourceChange.[Action,LogicalResourceId,ResourceType,Replacement]' --output text)"
      token="$(aws cloudformation describe-change-set --region "$REGION" --stack-name "$stack" --change-set-name "$name" \
        --next-token "$token" --query NextToken --output text)"
    else
      page="$(aws cloudformation describe-change-set --region "$REGION" --stack-name "$stack" --change-set-name "$name" \
        --query 'Changes[].ResourceChange.[Action,LogicalResourceId,ResourceType,Replacement]' --output text)"
      token="$(aws cloudformation describe-change-set --region "$REGION" --stack-name "$stack" --change-set-name "$name" \
        --query NextToken --output text)"
    fi
    changes="$(awk -F'\t' 'NF {
        mark = "  "
        if ($4 == "True") mark = "!!"
        else if ($4 == "Conditional") mark = "! "
        if ($1 == "Remove") mark = "!!"
        printf "  %s %-7s %-40s %s%s\n", mark, $1, $2, $3, ($4 == "True" ? "  REPLACED" : ($4 == "Conditional" ? "  may be replaced" : ""))
      }' <<<"$page")"
    [[ -z "$changes" ]] || echo "$changes"
    replace=$((replace + $(grep -c -e '  REPLACED' -e 'may be replaced' <<<"$changes" || true)))
    remove=$((remove + $(grep -c ' Remove ' <<<"$changes" || true)))
    [[ -n "$token" && "$token" != None ]] || break
  done
  if [[ $((replace + remove)) -gt 0 ]]; then
    echo "  !! $replace resources replaced or possibly replaced, $remove removed: a replaced table, key, bucket,"
    echo "  !! load balancer or namespace loses its data or its address (docs/aws-deployment.md#change-sets)"
  fi

  if [[ "$PLAN" == true ]]; then
    aws cloudformation delete-change-set --region "$REGION" --stack-name "$stack" --change-set-name "$name" >/dev/null
    echo "  plan only: change set deleted, $stack not changed"
    return 0
  fi
  if [[ "$YES" == false ]]; then
    [[ -t 0 ]] || fail "no terminal to confirm on: review with --plan, then pass --yes"
    read -r -p "  Type $stack to run this change set: " answer
    if [[ "$answer" != "$stack" ]]; then
      aws cloudformation delete-change-set --region "$REGION" --stack-name "$stack" --change-set-name "$name" >/dev/null
      fail "not confirmed; $stack not changed"
    fi
  fi
  aws cloudformation execute-change-set --region "$REGION" --stack-name "$stack" --change-set-name "$name"
  if [[ "$type" == CREATE ]]; then
    aws cloudformation wait stack-create-complete --region "$REGION" --stack-name "$stack" ||
      fail "creating $stack failed; see its events (docs/runbook.md#first-deployment-rolled-back)"
  else
    aws cloudformation wait stack-update-complete --region "$REGION" --stack-name "$stack" ||
      fail "updating $stack failed; CloudFormation rolls it back, see its events (docs/runbook.md#rollback)"
  fi
}

# A name a resource of the template takes from the stack name, which a
# retained resource of an earlier stack still holds: a first creation would
# fail on it late, after the network and load balancers are built.
retained_names() {
  awk -v stack="$1" '
    /TableName: !Sub .\$\{AWS::StackName\}-/ { s = $0; sub(/.*\$\{AWS::StackName\}/, stack, s); sub(/.$/, "", s); print "table " s }
    /Name: !Sub .\$\{AWS::StackName\}\// { s = $0; sub(/.*\$\{AWS::StackName\}/, stack, s); sub(/.$/, "", s); print "secret " s }
    /LogGroupName: !Sub .\/rcs\/\$\{AWS::StackName\}\// { s = $0; sub(/.*\$\{AWS::StackName\}/, stack, s); sub(/.$/, "", s); print "loggroup /rcs/" s }
  ' "$PLATFORM_TEMPLATE"
}

check_names_free() {
  local kind name taken=()
  while read -r kind name; do
    case "$kind" in
      table)
        if aws dynamodb describe-table --region "$REGION" --table-name "$name" >/dev/null 2>&1; then taken+=("table $name"); fi ;;
      secret)
        if aws secretsmanager describe-secret --region "$REGION" --secret-id "$name" >/dev/null 2>&1; then taken+=("secret $name"); fi ;;
      loggroup)
        if [[ "$(aws logs describe-log-groups --region "$REGION" --log-group-name-prefix "$name" \
          --query "logGroups[?logGroupName=='$name'] | length(@)" --output text)" != 0 ]]; then taken+=("log group $name"); fi ;;
    esac
  done < <(retained_names "$STACK")
  if [[ ${#taken[@]} -gt 0 ]]; then
    echo "deploy.sh: a first creation of $STACK would fail late: these names are taken, probably retained by an earlier stack:" >&2
    printf '  %s\n' "${taken[@]}" >&2
    echo "Delete or rename them first (docs/aws-deployment.md#teardown)." >&2
    exit 1
  fi
}

# vCPU a deployment needs at its peak: every service's tasks plus the one
# extra task of a rolling step (ADR 0003), all services rolling at once.
needed_vcpu() {
  local service count size total=0
  for service in Hss FtServer Relay Acs; do
    count="$(config_value "${service}DesiredCount")"
    size="$(config_value "${service}TaskSize")"
    [[ "$count" =~ ^[0-9]+$ && "$size" =~ ^[0-9]+x ]] || fail "${service}DesiredCount and ${service}TaskSize must be set"
    [[ "$count" -gt 0 ]] && count=$((count + 1))
    total=$((total + count * ${size%%x*}))
  done
  awk -v units="$total" 'BEGIN { printf "%.2f", units / 1024 }'
}

check_quota() {
  local quota needed
  needed="$(needed_vcpu)"
  if ! quota="$(aws service-quotas get-service-quota --region "$REGION" --service-code fargate \
    --quota-code "$FARGATE_VCPU_QUOTA" --query Quota.Value --output text 2>/dev/null)"; then
    echo "  warning: cannot read the Fargate vCPU quota; this deployment needs up to $needed vCPU" >&2
    return 0
  fi
  [[ "$quota" =~ ^[0-9]+(\.[0-9]+)?$ ]] || fail "unexpected Fargate vCPU quota: $quota"
  if awk -v q="$quota" -v n="$needed" 'BEGIN { exit !(n > q) }'; then
    fail "a rolling update needs up to $needed Fargate vCPU but the quota is $quota: request an increase of $FARGATE_VCPU_QUOTA first (docs/aws-deployment.md#prerequisites)"
  fi
  echo "  Fargate vCPU: up to $needed needed, quota $quota"
}

# The IAM ARN of the caller, as aws:PrincipalArn sees it: an assumed role is
# its role (with its path), a user is itself.
deploy_principal() {
  local arn="$1" role
  case "$arn" in
    arn:*:sts::*:assumed-role/*)
      role="${arn#*:assumed-role/}"
      role="${role%%/*}"
      aws iam get-role --role-name "$role" --query Role.Arn --output text ;;
    arn:*:iam::*:user/* | arn:*:iam::*:root)
      echo "$arn" ;;
    *)
      fail "cannot tell the deploying principal from $arn" ;;
  esac
}

prefix_list() {
  local id
  id="$(aws ec2 describe-managed-prefix-lists --region "$REGION" \
    --filters "Name=prefix-list-name,Values=com.amazonaws.$REGION.$1" \
    --query 'PrefixLists[0].PrefixListId' --output text)"
  [[ "$id" =~ ^pl-[0-9a-f]+$ ]] || fail "no managed prefix list com.amazonaws.$REGION.$1"
  echo "$id"
}

# ------------------------------------------------------------------ deploy

echo "stack       $STACK (registry $ECR_STACK)"
echo "region      $REGION"
echo "template    $TEMPLATE_REVISION"
echo "images      platform $IMAGE_TAG, acs $ACS_IMAGE_TAG"
echo "build       $([[ "$SKIP_BUILD" == true ]] && echo "no (--skip-build)" || echo yes)"
if [[ "$SKIP_BUILD" == true && "$IMAGE_TAG" != "$TEMPLATE_REVISION" ]]; then
  echo "            note: the template comes from $TEMPLATE_REVISION, the image from $IMAGE_TAG;"
  echo "            to roll the template back too, check out $IMAGE_TAG and run this from there"
fi
if [[ "$DRY_RUN" == true ]]; then
  echo "dry run     no AWS or Docker call is made"
  DEPLOY_PRINCIPAL="<the deploying principal>"
else
  # An assignment, so a failed call stops the script before anything else.
  IDENTITY="$(aws sts get-caller-identity --region "$REGION" --query Arn --output text)"
  echo "identity    $IDENTITY"
  DEPLOY_PRINCIPAL="$(deploy_principal "$IDENTITY")"
fi

# Both stacks are checked before anything is pushed or deployed.
check_updatable "$ECR_STACK"
check_updatable "$STACK"
if [[ "$DRY_RUN" == false ]]; then
  check_quota
  if ! stack_exists "$STACK"; then
    check_names_free
  fi
fi

echo
echo "[1/4] registry stack $ECR_STACK"
if [[ "$SKIP_BUILD" == true ]]; then
  [[ "$DRY_RUN" == true ]] || stack_exists "$ECR_STACK" ||
    fail "stack $ECR_STACK does not exist: --skip-build deploys images of an earlier deployment"
  echo "  not changed (--skip-build)"
else
  if [[ "$DRY_RUN" == false ]] && ! stack_exists "$ECR_STACK"; then
    for repo in "$STACK" "$STACK-acs"; do
      if aws ecr describe-repositories --region "$REGION" --repository-names "$repo" >/dev/null 2>&1; then
        fail "the repository $repo exists, probably retained by an earlier registry stack; delete it first (docs/aws-deployment.md#teardown)"
      fi
    done
  fi
  apply_change_set "$ECR_STACK" --template-body "file://$ECR_TEMPLATE" \
    "PlatformRepositoryName=$STACK" "AcsRepositoryName=$STACK-acs" \
    "UntaggedImageExpiryDays=$UNTAGGED_IMAGE_EXPIRY_DAYS" "MaxTaggedImages=$MAX_TAGGED_IMAGES"
  if [[ "$PLAN" == true && "$DRY_RUN" == false ]] && ! stack_exists "$ECR_STACK"; then
    echo
    echo "Plan stopped: the registry stack does not exist yet, so there is nothing to build into."
    exit 0
  fi
fi
PLATFORM_URI="$(stack_output "$ECR_STACK" PlatformRepositoryUri)"
ACS_URI="$(stack_output "$ECR_STACK" AcsRepositoryUri)"
TEMPLATE_BUCKET="$(stack_output "$ECR_STACK" TemplateBucketName)"

echo
echo "[2/4] platform image $IMAGE_TAG"
if image_exists "$PLATFORM_URI" "$IMAGE_TAG"; then
  [[ "$DRY_RUN" == true ]] || echo "  already in ECR"
elif [[ "$SKIP_BUILD" == true ]]; then
  fail "$PLATFORM_URI:$IMAGE_TAG is not in ECR: a rollback deploys only images pushed before"
else
  build_platform "$PLATFORM_URI"
fi
IMAGE_DIGEST="$DIGEST"
echo "  digest $IMAGE_DIGEST"

echo
echo "[3/4] acs image $ACS_IMAGE_TAG"
if image_exists "$ACS_URI" "$ACS_IMAGE_TAG"; then
  # The pinned release's tag may only ever hold the pinned bytes.
  if [[ "$DRY_RUN" == false && "$ACS_IMAGE_TAG" == "$ACS_VERSION" && "$DIGEST" != "$ACS_DIGEST" ]]; then
    fail "ECR holds $DIGEST under $ACS_URI:$ACS_VERSION, not the pinned $ACS_DIGEST"
  fi
  [[ "$DRY_RUN" == true ]] || echo "  already in ECR"
elif [[ "$SKIP_BUILD" == true ]]; then
  fail "$ACS_URI:$ACS_IMAGE_TAG is not in ECR: a rollback deploys only images pushed before"
else
  copy_acs "$ACS_URI"
fi
ACS_IMAGE_DIGEST="$DIGEST"
[[ "$DRY_RUN" == false || "$ACS_IMAGE_TAG" != "$ACS_VERSION" ]] || ACS_IMAGE_DIGEST="$ACS_DIGEST"
echo "  digest $ACS_IMAGE_DIGEST"

echo
echo "[4/4] platform stack $STACK"
if [[ "$DRY_RUN" == true ]]; then
  S3_PREFIX_LIST="<pl of com.amazonaws.$REGION.s3>"
  DYNAMODB_PREFIX_LIST="<pl of com.amazonaws.$REGION.dynamodb>"
  PREVIOUS_IMAGE_TAG="<the ImageTag the stack runs now>"
else
  S3_PREFIX_LIST="$(prefix_list s3)"
  DYNAMODB_PREFIX_LIST="$(prefix_list dynamodb)"
  # What runs now becomes the rollback target, unless this deployment keeps
  # the image (a configuration change), which keeps the recorded one.
  PREVIOUS_IMAGE_TAG=none
  if stack_exists "$STACK"; then
    current="$(optional_output "$STACK" ImageTag)"
    if [[ -n "$current" && "$current" != "$IMAGE_TAG" ]]; then
      PREVIOUS_IMAGE_TAG="$current"
    else
      PREVIOUS_IMAGE_TAG="$(optional_output "$STACK" PreviousImageTag)"
      PREVIOUS_IMAGE_TAG="${PREVIOUS_IMAGE_TAG:-none}"
    fi
    echo "  running now: ${current:-unknown}"
  fi
fi
PAIRS=(
  "EcrStackName=$ECR_STACK"
  "ImageTag=$IMAGE_TAG" "ImageDigest=$IMAGE_DIGEST"
  "AcsImageTag=$ACS_IMAGE_TAG" "AcsImageDigest=$ACS_IMAGE_DIGEST"
  "S3PrefixListId=$S3_PREFIX_LIST" "DynamoDbPrefixListId=$DYNAMODB_PREFIX_LIST"
  "TemplateRevision=$TEMPLATE_REVISION" "PreviousImageTag=$PREVIOUS_IMAGE_TAG"
  "DeployPrincipalArn=$DEPLOY_PRINCIPAL"
)
for ((i = 0; i < ${#CONFIG_KEYS[@]}; i++)); do
  PAIRS+=("${CONFIG_KEYS[$i]}=${CONFIG_VALUES[$i]}")
done
# The template is larger than CloudFormation accepts inline, so it goes
# through the registry stack's bucket, under its content hash.
if command -v sha256sum >/dev/null; then
  HASH="$(sha256sum "$PLATFORM_TEMPLATE" | cut -c1-16)"
else
  HASH="$(shasum -a 256 "$PLATFORM_TEMPLATE" | cut -c1-16)"
fi
KEY="$STACK/platform-$HASH.yaml"
run aws s3 cp --region "$REGION" --only-show-errors "$PLATFORM_TEMPLATE" "s3://$TEMPLATE_BUCKET/$KEY"
apply_change_set "$STACK" --template-url "https://$TEMPLATE_BUCKET.s3.$REGION.amazonaws.com/$KEY" "${PAIRS[@]}"

if [[ "$DRY_RUN" == true ]]; then
  echo
  echo "Dry run: nothing was built, pushed or deployed."
  exit 0
fi
if [[ "$PLAN" == true ]]; then
  echo
  echo "Plan only: the images are in ECR; no stack was changed."
  exit 0
fi

echo
aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output table

cat <<DONE

Deployed $STACK: template $TEMPLATE_REVISION, platform $IMAGE_TAG, acs $ACS_IMAGE_TAG.
Next (docs/aws-deployment.md#after-the-first-deployment): point the
operator's names at NlbDnsName and AlbDnsName, and subscribe the on-call
address to AlarmTopic.
Roll back the image with the same --config:
  scripts/deploy.sh --config $CONFIG --stack-name $STACK --region $REGION --skip-build --image-tag $PREVIOUS_IMAGE_TAG
DONE
