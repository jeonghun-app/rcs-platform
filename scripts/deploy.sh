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

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORM_TEMPLATE="$ROOT/infra/platform.yaml"
ECR_TEMPLATE="$ROOT/infra/ecr.yaml"

# Platform parameters this script sets itself; the config file may not.
MANAGED_PARAMETERS=(EcrStackName ImageTag AcsImageTag)

CONFIG=""
STACK="rcs-platform"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
IMAGE_TAG=""
ACS_IMAGE_TAG=""
SKIP_BUILD=false
DRY_RUN=false

usage() {
  cat <<'USAGE'
Usage: scripts/deploy.sh --config FILE [options]

  --config FILE         Platform parameters, one Key=Value per line, every
                        parameter of infra/platform.yaml except EcrStackName,
                        ImageTag and AcsImageTag (see infra/platform.example.params)
  --stack-name NAME     Platform stack (default rcs-platform). The registry
                        stack is NAME-ecr, its repositories NAME and NAME-acs.
  --region REGION       Default $AWS_REGION, $AWS_DEFAULT_REGION or ap-northeast-2
  --skip-build          Build and push nothing: deploy images already in ECR.
                        Needs --image-tag. This is the rollback.
  --image-tag TAG       Platform image to deploy; only with --skip-build.
                        Without it the tag is `git describe` of a clean tree.
  --acs-image-tag TAG   acs image to deploy; only with --skip-build. Default
                        the pinned ACS_VERSION, copied from GHCR by digest.
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
  # The file is never run by a shell: values are taken literally, and quotes
  # or spaces around one are a mistake.
  case "$value" in
    \"* | \'* | [[:space:]]* | *[[:space:]])
      PROBLEMS+=("line $number: $key: values are literal; remove the quotes or the spaces around it")
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

# ------------------------------------------------------------------- tags

if [[ "$DRY_RUN" == false ]]; then
  command -v aws >/dev/null || fail "the aws CLI is not installed"
  if [[ "$SKIP_BUILD" == false ]]; then
    for tool in docker git make; do
      command -v "$tool" >/dev/null || fail "$tool is not installed"
    done
    docker buildx version >/dev/null 2>&1 || fail "docker buildx is not installed (it copies the acs image)"
  fi
fi

if [[ "$SKIP_BUILD" == false ]]; then
  [[ -z "$(git -C "$ROOT" status --porcelain)" ]] ||
    fail "the working tree has uncommitted or untracked files: commit them first, so the image tag names what is in the image"
  IMAGE_TAG="$(git -C "$ROOT" describe --tags --always)"
fi
ACS_IMAGE_TAG="${ACS_IMAGE_TAG:-$ACS_VERSION}"
valid_tag "$IMAGE_TAG" || usage_error "not an image tag: $IMAGE_TAG"
valid_tag "$ACS_IMAGE_TAG" || usage_error "not an image tag: $ACS_IMAGE_TAG"

ECR_STACK="$STACK-ecr"

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

# Refuses a stack that CloudFormation cannot update as it stands.
check_updatable() {
  local status
  [[ "$DRY_RUN" == true ]] && return 0
  status="$(stack_status "$1")"
  case "$status" in
    "" | CREATE_COMPLETE | UPDATE_COMPLETE | UPDATE_ROLLBACK_COMPLETE | IMPORT_COMPLETE | IMPORT_ROLLBACK_COMPLETE) ;;
    ROLLBACK_COMPLETE)
      fail "stack $1 is ROLLBACK_COMPLETE: its creation failed and it cannot be updated. Read its events, then delete it (scripts/teardown.sh) and deploy again (docs/runbook.md#first-deployment-rolled-back)" ;;
    *_IN_PROGRESS)
      fail "stack $1 is $status: wait for it to finish" ;;
    *)
      fail "stack $1 is $status: resolve that first (docs/runbook.md#rollback)" ;;
  esac
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

# ------------------------------------------------------------------ deploy

echo "stack       $STACK (registry $ECR_STACK)"
echo "region      $REGION"
echo "images      platform $IMAGE_TAG, acs $ACS_IMAGE_TAG"
echo "build       $([[ "$SKIP_BUILD" == true ]] && echo "no (--skip-build)" || echo yes)"
if [[ "$DRY_RUN" == true ]]; then
  echo "dry run     no AWS or Docker call is made"
else
  echo "identity    $(aws sts get-caller-identity --region "$REGION" --query Arn --output text)"
fi

# Both stacks are checked before anything is pushed or deployed.
check_updatable "$ECR_STACK"
check_updatable "$STACK"

echo
echo "[1/4] registry stack $ECR_STACK"
if [[ "$SKIP_BUILD" == true ]]; then
  if [[ "$DRY_RUN" == false ]]; then
    # An assignment, so that a failed read stops the script (set -e).
    ecr_status="$(stack_status "$ECR_STACK")"
    [[ -n "$ecr_status" ]] ||
      fail "stack $ECR_STACK does not exist: --skip-build deploys images of an earlier deployment"
  fi
  echo "  not changed (--skip-build)"
else
  run aws cloudformation deploy --region "$REGION" --stack-name "$ECR_STACK" \
    --template-file "$ECR_TEMPLATE" --no-fail-on-empty-changeset \
    --tags Application=rcs-platform \
    --parameter-overrides "PlatformRepositoryName=$STACK" "AcsRepositoryName=$STACK-acs" \
    "UntaggedImageExpiryDays=$UNTAGGED_IMAGE_EXPIRY_DAYS" "MaxTaggedImages=$MAX_TAGGED_IMAGES"
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

echo
echo "[4/4] platform stack $STACK"
OVERRIDES=("EcrStackName=$ECR_STACK" "ImageTag=$IMAGE_TAG" "AcsImageTag=$ACS_IMAGE_TAG")
for ((i = 0; i < ${#CONFIG_KEYS[@]}; i++)); do
  OVERRIDES+=("${CONFIG_KEYS[$i]}=${CONFIG_VALUES[$i]}")
done
# The template is larger than CloudFormation accepts inline, so it goes
# through the registry stack's bucket.
run aws cloudformation deploy --region "$REGION" --stack-name "$STACK" \
  --template-file "$PLATFORM_TEMPLATE" --s3-bucket "$TEMPLATE_BUCKET" --s3-prefix "$STACK" \
  --capabilities CAPABILITY_IAM --no-fail-on-empty-changeset \
  --tags Application=rcs-platform \
  --parameter-overrides "${OVERRIDES[@]}"

echo
run aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output table

if [[ "$DRY_RUN" == true ]]; then
  echo
  echo "Dry run: nothing was built, pushed or deployed."
  exit 0
fi

cat <<DONE

Deployed $STACK with platform $IMAGE_TAG and acs $ACS_IMAGE_TAG.
Next (docs/aws-deployment.md#after-the-first-deployment): point the
operator's names at NlbDnsName and AlbDnsName, and subscribe the on-call
address to AlarmTopic.
Roll back with the same --config and:
  scripts/deploy.sh --config $CONFIG --stack-name $STACK --region $REGION --skip-build --image-tag <previous tag>
DONE
