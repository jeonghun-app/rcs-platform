#!/usr/bin/env bash
#
# Deletes the RCS platform stack (docs/aws-deployment.md#teardown).
#
# Data survives it: the template retains the tables, the files bucket, the HSS
# keyring key and the VPC flow log group, and this script lists them at the
# end with their names, for recovery or for deleting by hand. The secrets are
# deleted with the stack. --with-registry deletes the registry stack too,
# whose image repositories are retained as well.
#
# This deletes resources in the AWS account the credentials point at, after
# the stack name is typed (or given with --confirm). Run it only with the
# approval docs/aws-deployment.md asks for. --dry-run prints the commands
# without calling AWS.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

STACK="rcs-platform"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-northeast-2}}"
CONFIRM=""
WITH_REGISTRY=false
DRY_RUN=false

usage() {
  cat <<'USAGE'
Usage: scripts/teardown.sh [options]

  --stack-name NAME   Platform stack (default rcs-platform); the registry
                      stack is NAME-ecr
  --region REGION     Default $AWS_REGION, $AWS_DEFAULT_REGION or ap-northeast-2
  --with-registry     Also delete the registry stack (its repositories are
                      retained)
  --confirm NAME      The stack name, instead of typing it when asked
  --dry-run           Print the commands without calling AWS
  -h, --help          Show this help
USAGE
}

fail() {
  echo "teardown.sh: $*" >&2
  exit 1
}

usage_error() {
  echo "teardown.sh: $*" >&2
  echo "Run scripts/teardown.sh --help for the options." >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stack-name | --region | --confirm)
      [[ $# -ge 2 ]] || usage_error "$1 needs a value"
      case "$1" in
        --stack-name) STACK="$2" ;;
        --region) REGION="$2" ;;
        --confirm) CONFIRM="$2" ;;
      esac
      shift 2
      ;;
    --with-registry) WITH_REGISTRY=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage_error "unknown option: $1" ;;
  esac
done

[[ "$STACK" =~ ^[a-z][a-z0-9-]{0,39}$ ]] || usage_error "not a stack name of deploy.sh: $STACK"
[[ "$REGION" =~ ^[a-z]{2}(-[a-z]+)+-[0-9]$ ]] || usage_error "not a region: $REGION"
ECR_STACK="$STACK-ecr"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Logical ids a template keeps on stack deletion (DeletionPolicy: Retain).
retained_resources() {
  awk '/^Resources:/ { p = 1; next }
       p && /^[^[:space:]#]/ { p = 0 }
       p && /^  [A-Za-z0-9]+:[[:space:]]*$/ { id = $1; sub(/:.*/, "", id) }
       p && /^    DeletionPolicy:[[:space:]]*Retain[[:space:]]*$/ { print id }' "$1"
}

run() {
  if [[ "$DRY_RUN" == true ]]; then
    printf '+'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

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

# Logical id, type and physical id of each resource, one per line.
# Logical id, type, physical id and status of each resource, one per line.
# A stack whose creation rolled back still lists the resources it deleted,
# as DELETE_COMPLETE.
stack_resources() {
  aws cloudformation list-stack-resources --region "$REGION" --stack-name "$1" \
    --query 'StackResourceSummaries[].[LogicalResourceId,ResourceType,PhysicalResourceId,ResourceStatus]' --output text
}

# The template the stack was deployed with, which is what decides what it
# retains; a checkout of another commit may differ.
deployed_template() {
  local file="$WORK/$1.template"
  aws cloudformation get-template --region "$REGION" --stack-name "$1" --template-stage Original \
    --query TemplateBody --output text >"$file"
  echo "$file"
}

# Turns a load balancer's deletion protection on or off. One already gone
# (a rolled-back creation deleted it) is skipped.
set_protection() {
  local arn="$1" value="$2" out
  if out="$(aws elbv2 modify-load-balancer-attributes --region "$REGION" --load-balancer-arn "$arn" \
    --attributes "Key=deletion_protection.enabled,Value=$value" 2>&1 >/dev/null)"; then
    return 0
  elif [[ "$out" == *LoadBalancerNotFound* ]]; then
    echo "  $arn no longer exists"
    return 1
  fi
  fail "cannot change deletion protection of $arn: $out"
}

# Prints the retained resources of a stack from its resource list.
report_retained() {
  local template="$1" resources="$2" id line found=false
  while IFS= read -r id; do
    if [[ "$DRY_RUN" == true ]]; then
      echo "  $id"
      found=true
      continue
    fi
    line="$(awk -v id="$id" '$1 == id && $4 != "DELETE_COMPLETE" { print "  " $1 "  " $2 "  " $3 }' <<<"$resources")"
    if [[ -n "$line" ]]; then
      echo "$line"
      found=true
    fi
  done < <(retained_resources "$template")
  [[ "$found" == true ]] || echo "  none"
}

# Deletes a stack and waits; a stack that does not exist is skipped. The
# retained resources are listed afterwards.
delete_stack() {
  local stack="$1" template="$2" status resources="" arn lifted=()
  if [[ "$DRY_RUN" == false ]]; then
    status="$(stack_status "$stack")"
    case "$status" in
      "") echo "  $stack does not exist"; return 0 ;;
      DELETE_COMPLETE) echo "  $stack is already deleted"; return 0 ;;
      # The empty shell a first change set left: nothing in it to keep.
      REVIEW_IN_PROGRESS) ;;
      *_IN_PROGRESS) fail "stack $stack is $status: wait for it to finish" ;;
    esac
    resources="$(stack_resources "$stack")"
    [[ "$status" == REVIEW_IN_PROGRESS ]] || template="$(deployed_template "$stack")"
  fi

  # Load balancers have deletion protection in prod, which would fail the
  # deletion halfway.
  if [[ "$DRY_RUN" == true ]]; then
    if grep -q 'Type: AWS::ElasticLoadBalancingV2::LoadBalancer$' "$template"; then
      run aws elbv2 modify-load-balancer-attributes --region "$REGION" \
        --load-balancer-arn "<each load balancer of $stack>" \
        --attributes Key=deletion_protection.enabled,Value=false
    fi
  else
    while IFS= read -r arn; do
      [[ -n "$arn" ]] || continue
      if set_protection "$arn" false; then
        echo "  deletion protection off: $arn"
        lifted+=("$arn")
      fi
    done < <(awk '$2 == "AWS::ElasticLoadBalancingV2::LoadBalancer" && $4 != "DELETE_COMPLETE" { print $3 }' <<<"$resources")
  fi

  run aws cloudformation delete-stack --region "$REGION" --stack-name "$stack"
  if ! run aws cloudformation wait stack-delete-complete --region "$REGION" --stack-name "$stack"; then
    # The stack stays, so its load balancers get their protection back:
    # a later deployment would not restore it (the template did not change).
    for arn in ${lifted[@]+"${lifted[@]}"}; do
      if set_protection "$arn" true; then echo "  deletion protection back on: $arn"; fi
    done
    fail "deleting $stack failed; see its events: aws cloudformation describe-stack-events --region $REGION --stack-name $stack (docs/runbook.md#teardown-failed)"
  fi
  if [[ "$DRY_RUN" == true ]]; then
    echo "  would retain, with their data, those of these that exist:"
  else
    echo "  deleted $stack. Retained, still billed and still holding data:"
  fi
  report_retained "$template" "$resources"
}

echo "stack       $STACK$([[ "$WITH_REGISTRY" == true ]] && echo " and $ECR_STACK")"
echo "region      $REGION"
if [[ "$DRY_RUN" == true ]]; then
  echo "dry run     no AWS call is made"
else
  command -v aws >/dev/null || fail "the aws CLI is not installed"
  echo "identity    $(aws sts get-caller-identity --region "$REGION" --query Arn --output text)"
  if [[ -z "$CONFIRM" ]]; then
    [[ -t 0 ]] || fail "no terminal to confirm on: pass --confirm $STACK"
    read -r -p "This deletes the stack and every service in it. Type the stack name to go on: " CONFIRM
  fi
  [[ "$CONFIRM" == "$STACK" ]] || fail "the name did not match $STACK; nothing was deleted"
fi

echo
echo "[1/2] platform stack $STACK"
delete_stack "$STACK" "$ROOT/infra/platform.yaml"

echo
echo "[2/2] registry stack $ECR_STACK"
if [[ "$WITH_REGISTRY" == false ]]; then
  echo "  kept (pass --with-registry to delete it)"
else
  # CloudFormation deletes only an empty bucket; the templates in it are
  # copies of infra/platform.yaml.
  bucket="<TemplateBucketName of $ECR_STACK>"
  if [[ "$DRY_RUN" == false ]]; then
    ecr_status="$(stack_status "$ECR_STACK")"
    if [[ -n "$ecr_status" ]]; then
      bucket="$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$ECR_STACK" \
        --query "Stacks[0].Outputs[?OutputKey=='TemplateBucketName'].OutputValue" --output text)"
    fi
  fi
  if [[ "$DRY_RUN" == true || ( -n "$bucket" && "$bucket" != None && "$bucket" != "<"* ) ]]; then
    run aws s3 rm --region "$REGION" --recursive --quiet "s3://$bucket"
  fi
  delete_stack "$ECR_STACK" "$ROOT/infra/ecr.yaml"
fi

if [[ "$DRY_RUN" == true ]]; then
  echo
  echo "Dry run: nothing was deleted."
  exit 0
fi

cat <<'DONE'

The retained resources keep their data and their charges. A stack of the
same name cannot be created while its tables still exist; see
docs/aws-deployment.md#teardown before deleting or reusing them.
DONE
