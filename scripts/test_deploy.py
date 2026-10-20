"""Tests of scripts/deploy.sh, scripts/teardown.sh and scripts/rotate-token.sh
against stand-ins.

aws, docker, git and make are replaced by a stub on PATH that records every
call and answers from a small state file, so the scripts run end to end
without an AWS account, Docker or network. Run with
python3 -m unittest discover -s scripts -p 'test_*.py' in the infra tools
image (make infra-lint).
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import tempfile
import unittest

import check_infra

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "scripts" / "deploy.sh"
TEARDOWN = ROOT / "scripts" / "teardown.sh"
ROTATE = ROOT / "scripts" / "rotate-token.sh"
EXAMPLE = ROOT / "infra" / "platform.example.params"
PLATFORM = ROOT / "infra" / "platform.yaml"
ECR = ROOT / "infra" / "ecr.yaml"

MANAGED = {"EcrStackName", "ImageTag", "ImageDigest", "AcsImageTag", "AcsImageDigest", "S3PrefixListId",
           "DynamoDbPrefixListId", "TemplateRevision", "PreviousImageTag", "DeployPrincipalArn",
           "NlbReusedAddressA", "NlbReusedAddressB"}
REGISTRY = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com"
PLATFORM_URI = f"{REGISTRY}/rcs-platform"
ACS_URI = f"{REGISTRY}/rcs-platform-acs"
BUCKET = "rcs-platform-ecr-templatebucket-example"
ACS_DIGEST = "sha256:00956e9fe4d5865cf5e39292122ec1df78e34993f5c9d07928fff836af5f33b2"
ACS_SOURCE = "ghcr.io/jeonghun-app/auto-configuration-server"
PUSHED = "sha256:" + "ab" * 32
OLD = "sha256:" + "cd" * 32
TAG = "v0.1.0-3-gabcdef0"

STUB = r'''#!/usr/bin/env python3
import json, os, sys

tool = os.path.basename(sys.argv[0])
args = sys.argv[1:]
path = os.environ["STUB_STATE"]
with open(path) as f:
    state = json.load(f)

def save():
    with open(path, "w") as f:
        json.dump(state, f)

def flag(name):
    return args[args.index(name) + 1] if name in args else None

def fail(message, code=254):
    sys.stderr.write(message + "\n")
    sys.exit(code)

record = [tool, args]
if tool == "aws" and "--parameters" in args:
    record.append(json.load(open(flag("--parameters")[len("file://"):])))
if tool == "aws" and args[:2] == ["secretsmanager", "put-secret-value"]:
    record.append("<value>")
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps(record + [os.environ.get("DOCKER_DEFAULT_PLATFORM", "")]) + "\n")

stack = flag("--stack-name")
query = flag("--query") or ""
cmd = args[:2]
if tool == "aws":
    if cmd == ["sts", "get-caller-identity"]:
        if state.get("sts_fails"):
            fail("Unable to locate credentials", 255)
        print(state["identity"])
    elif cmd == ["iam", "get-role"]:
        print("arn:aws:iam::123456789012:role/" + flag("--role-name"))
    elif cmd == ["service-quotas", "get-service-quota"]:
        quota = state.get("quotas", {}).get(flag("--quota-code"), state["quota"])
        if quota is None:
            fail("AccessDenied")
        print(quota)
    elif cmd == ["dynamodb", "describe-table"]:
        if "table " + flag("--table-name") not in state["taken"]:
            fail("ResourceNotFoundException")
    elif cmd == ["secretsmanager", "describe-secret"]:
        if "secret " + flag("--secret-id") not in state["taken"]:
            fail("ResourceNotFoundException")
    elif cmd == ["logs", "describe-log-groups"]:
        print(1 if "log group " + flag("--log-group-name-prefix") in state["taken"] else 0)
    elif cmd == ["ecr", "describe-repositories"]:
        if "repository " + flag("--repository-names") not in state["taken"]:
            fail("RepositoryNotFoundException")
    elif cmd == ["ec2", "describe-addresses"]:
        ids = flag("--allocation-ids")
        if ids is None:
            print(len(state.get("addresses", {})))
        elif ids not in state.get("addresses", {}):
            fail("InvalidAllocationID.NotFound")
        else:
            print(state["addresses"][ids])
    elif cmd == ["ec2", "describe-managed-prefix-lists"]:
        print("pl-0a1b2c3d" if flag("--filters").endswith(".s3") else "pl-1a2b3c4d")
    elif cmd == ["cloudformation", "describe-stacks"]:
        if stack not in state["stacks"]:
            fail(f"An error occurred (ValidationError): Stack with id {stack} does not exist")
        if "StackStatus" in query:
            print(state["stacks"][stack])
        elif "OutputKey==" in query:
            key = query.split("OutputKey=='")[1].split("'")[0]
            print(state["outputs"].get(stack, {}).get(key, "None"))
        else:
            print("outputs table")
    elif cmd == ["cloudformation", "create-change-set"]:
        if stack not in state["stacks"]:
            state["stacks"][stack] = "REVIEW_IN_PROGRESS"
        state["changeset_type"][stack] = flag("--change-set-type")
        save()
    elif cmd == ["cloudformation", "wait"] and args[2] == "change-set-create-complete":
        if stack in state["empty"]:
            sys.exit(255)
    elif cmd == ["cloudformation", "describe-change-set"]:
        if query == "StatusReason":
            print("The submitted information didn't contain changes. Submit different information to create a change set.")
        elif query == "NextToken":
            print("None")
        else:
            for line in state["changes"].get(stack, [["Add", "Thing", "AWS::X::Y", ""]]):
                print("\t".join(line))
    elif cmd == ["cloudformation", "execute-change-set"]:
        state["stacks"][stack] = "UPDATE_COMPLETE" if state["changeset_type"][stack] == "UPDATE" else "CREATE_COMPLETE"
        save()
    elif cmd == ["cloudformation", "wait"] and args[2] == "stack-delete-complete":
        if state.get("delete_fails"):
            sys.exit(255)
    elif cmd == ["cloudformation", "list-stack-resources"]:
        for line in state["resources"].get(stack, []):
            print("\t".join(line))
    elif cmd == ["cloudformation", "get-template"]:
        sys.stdout.write(open(state["deployed_templates"][stack]).read())
    elif cmd == ["ecr", "describe-images"]:
        image = flag("--repository-name") + ":" + flag("--image-ids").split("=", 1)[1]
        if image not in state["images"]:
            fail("An error occurred (ImageNotFoundException): no such image")
        print(state["images"][image])
    elif cmd == ["ecr", "get-login-password"]:
        print("password")
    elif cmd == ["elbv2", "modify-load-balancer-attributes"]:
        if flag("--load-balancer-arn") in state["gone"]:
            fail("An error occurred (LoadBalancerNotFound): not found")
    elif cmd == ["secretsmanager", "get-secret-value"]:
        print(state["secrets"][flag("--secret-id")])
    elif cmd == ["secretsmanager", "put-secret-value"]:
        state["secrets"][flag("--secret-id")] = open(flag("--secret-string")[len("file://"):]).read()
        save()
    elif cmd == ["secretsmanager", "get-random-password"]:
        state["random"] += 1
        save()
        print(("R%d" % state["random"]).ljust(64, "x"))
    elif cmd == ["ecs", "describe-services"]:
        queue = state["rollouts"].get(flag("--services"), [])
        line = queue.pop(0) if queue else "1\tCOMPLETED\t2\t2"
        save()
        print(line)
elif tool == "git":
    while args and args[0] in ("-C", "-c"):
        args = args[2:]
    if args[:2] == ["status", "--porcelain"]:
        sys.stdout.write(state["dirty"])
    elif args[:1] == ["describe"]:
        print(state["describe"])
elif tool == "docker" and args[:1] == ["login"]:
    sys.stdin.read()
elif tool == "docker" and args[:1] == ["push"]:
    state["images"][args[1].split("/", 1)[1]] = state["pushed_digest"]
    save()
elif tool == "docker" and args[:3] == ["buildx", "imagetools", "create"]:
    state["images"][flag("--tag").split("/", 1)[1]] = state["copied_digest"]
    save()
'''


class Stubbed(unittest.TestCase):
    """Runs a script with the stubs first on PATH."""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        bin_dir = self.dir / "bin"
        bin_dir.mkdir()
        for tool in ("aws", "docker", "git", "make"):
            stub = bin_dir / tool
            stub.write_text(STUB)
            stub.chmod(0o755)
        self.log = self.dir / "calls.jsonl"
        self.log.touch()
        self.state_file = self.dir / "state.json"
        self.state = {
            "identity": "arn:aws:sts::123456789012:assumed-role/Deployer/someone",
            "quota": "6.0",
            "taken": [],
            "stacks": {},
            "changeset_type": {},
            "empty": [],
            "changes": {},
            "outputs": {"rcs-platform-ecr": {
                "PlatformRepositoryUri": PLATFORM_URI, "AcsRepositoryUri": ACS_URI, "TemplateBucketName": BUCKET}},
            "resources": {},
            "deployed_templates": {"rcs-platform": str(PLATFORM), "rcs-platform-ecr": str(ECR)},
            "gone": [],
            "images": {},
            "pushed_digest": PUSHED,
            "copied_digest": ACS_DIGEST,
            "secrets": {},
            "random": 0,
            "rollouts": {},
            "dirty": "",
            "describe": TAG,
        }
        self.env = {
            "PATH": f"{bin_dir}:/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.dir),
            "STUB_LOG": str(self.log),
            "STUB_STATE": str(self.state_file),
            "ROTATE_POLL_SECONDS": "0",
        }

    def tearDown(self):
        subprocess.run(["rm", "-rf", str(self.dir)], check=True)

    def run_script(self, script, *args, env=None) -> subprocess.CompletedProcess:
        self.state_file.write_text(json.dumps(self.state))
        result = subprocess.run(["bash", str(script), *args], env={**self.env, **(env or {})}, cwd=self.dir,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)
        self.state = json.loads(self.state_file.read_text())
        return result

    def records(self) -> list[list]:
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def calls(self, tool=None) -> list[list[str]]:
        """Calls of a tool, without the check that docker has buildx."""
        return [r[1] for r in self.records()
                if (tool is None or r[0] == tool) and r[1] != ["buildx", "version"]]

    def call(self, tool, *prefix) -> list[str]:
        matches = [a for a in self.calls(tool) if a[:len(prefix)] == list(prefix)]
        self.assertEqual(len(matches), 1, f"{tool} {' '.join(prefix)}: {matches}")
        return matches[0]

    def position(self, tool, *prefix) -> int:
        [index] = [i for i, r in enumerate(self.records()) if r[0] == tool and r[1][:len(prefix)] == list(prefix)]
        return index

    def aws(self, *prefix, stack=None) -> list[list[str]]:
        return [a for a in self.calls("aws") if a[:len(prefix)] == list(prefix)
                and (stack is None or a[a.index("--stack-name") + 1] == stack)]

    def change_set(self, stack) -> dict:
        """The parameters of the one change set created for a stack."""
        found = [r[2] for r in self.records() if r[0] == "aws" and r[1][:2] == ["cloudformation", "create-change-set"]
                 and r[1][r[1].index("--stack-name") + 1] == stack]
        self.assertEqual(len(found), 1, f"change sets of {stack}: {found}")
        pairs = [(p["ParameterKey"], p["ParameterValue"]) for p in found[0]]
        values = dict(pairs)
        self.assertEqual(len(values), len(pairs), "a parameter is passed twice")
        return values

    def config(self, *extra: str, drop: tuple[str, ...] = (), replace: dict | None = None) -> pathlib.Path:
        replace = replace or {}
        lines = []
        for line in EXAMPLE.read_text().splitlines():
            key = line.split("=", 1)[0]
            if key in drop:
                continue
            lines.append(f"{key}={replace[key]}" if key in replace else line)
        path = self.dir / "test.params"
        path.write_text("\n".join(lines + list(extra)) + "\n")
        return path


def example_values() -> dict[str, str]:
    values = {}
    for line in EXAMPLE.read_text().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


def deploy(*args):
    return ("--config", str(EXAMPLE), "--yes", *args)


class DeployConfig(Stubbed):
    """The config names every parameter; mistakes stop before any call."""

    def test_the_example_names_every_parameter_the_script_does_not_set(self):
        parameters = set(check_infra.load(str(PLATFORM))["Parameters"])
        self.assertEqual(set(example_values()), parameters - MANAGED)

    def test_the_script_sets_exactly_the_managed_parameters(self):
        script = DEPLOY.read_text()
        listed = re.search(r"MANAGED_PARAMETERS=\(([^)]*)\)", script, re.S)[1].split()
        self.assertEqual(set(listed), MANAGED)

    def test_a_dry_run_calls_neither_aws_nor_docker(self):
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE), "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([a[2] for a in self.calls("git")], ["status", "describe"])
        self.assertEqual(self.calls("aws") + self.calls("docker") + self.calls("make"), [])
        self.assertIn("Dry run: nothing was built, pushed or deployed.", result.stdout)

    def test_a_dry_run_shows_every_parameter_once(self):
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE), "--dry-run")
        listing = result.stdout.split("[4/4]")[1].split("  parameters:")[1].split("+ (describe")[0]
        passed = [line.strip().split("=", 1)[0] for line in listing.splitlines() if line.strip()]
        self.assertEqual(sorted(passed), sorted(check_infra.load(str(PLATFORM))["Parameters"]))

    def test_a_missing_parameter_is_refused(self):
        result = self.run_script(DEPLOY, "--config", str(self.config(drop=("FtRealm",))), "--dry-run")
        self.assertEqual(result.returncode, 2)
        self.assertIn("FtRealm is missing", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_every_mistake_is_reported_at_once(self):
        path = self.config("Colour=blue", "Environment=prod", "ImageTag=v9", "ImageDigest=x",
                           "WafRateLimit=\"2000\"", "not a line", replace={"FtHostName": "ft.example.com # the FT name"})
        result = self.run_script(DEPLOY, "--config", str(path), "--dry-run")
        self.assertEqual(result.returncode, 2)
        for fragment in ("Colour is not a parameter", "Environment is set twice",
                         "ImageTag is set by deploy.sh", "ImageDigest is set by deploy.sh",
                         "WafRateLimit: values are literal", "expected Key=Value",
                         "FtHostName: comments go on their own line"):
            self.assertIn(fragment, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_an_image_tag_without_skip_build_is_refused(self):
        result = self.run_script(DEPLOY, *deploy("--image-tag", "v1"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("use them with --skip-build", result.stderr)

    def test_an_invalid_image_tag_is_refused(self):
        for tag in ("bad tag", "-v1", ".v1", "v1/2"):
            with self.subTest(tag=tag):
                result = self.run_script(DEPLOY, *deploy("--skip-build", "--image-tag", tag))
                self.assertEqual(result.returncode, 2)
                self.assertIn("not an image tag", result.stderr)

    def test_a_dirty_tree_is_refused_for_builds_and_rollbacks(self):
        for dirty in (" M infra/platform.yaml\n", "?? notes.txt\n"):
            for args in ((), ("--skip-build", "--image-tag", "v0.0.9")):
                with self.subTest(dirty=dirty, args=args):
                    self.state["dirty"] = dirty
                    result = self.run_script(DEPLOY, *deploy(*args))
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("uncommitted or untracked files", result.stderr)
                    self.assertEqual(self.calls("aws"), [])

    def test_a_failed_identity_call_stops_everything(self):
        self.state["sts_fails"] = True
        result = self.run_script(DEPLOY, *deploy())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([a[:2] for a in self.calls("aws")], [["sts", "get-caller-identity"]])


class Deploy(Stubbed):
    """A deployment against the stubs, from an empty account to a rollback."""

    def existing(self, image_tag="v0.0.9", previous="none"):
        self.state["stacks"] = {"rcs-platform-ecr": "UPDATE_COMPLETE", "rcs-platform": "UPDATE_COMPLETE"}
        self.state["outputs"]["rcs-platform"] = {"ImageTag": image_tag, "PreviousImageTag": previous}

    def test_a_first_deployment_builds_pushes_and_passes_every_parameter(self):
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 0, result.stderr)

        self.assertEqual(self.change_set("rcs-platform-ecr"), {
            "PlatformRepositoryName": "rcs-platform", "AcsRepositoryName": "rcs-platform-acs",
            "UntaggedImageExpiryDays": "7", "MaxTaggedImages": "30"})
        make = self.call("make")
        self.assertIn(f"IMAGE={PLATFORM_URI}", make)
        self.assertIn(f"VERSION={TAG}", make)
        [platform] = [r[2] for r in self.records() if r[0] == "make"]
        self.assertEqual(platform, "linux/amd64")
        copy = self.call("docker", "buildx", "imagetools", "create")
        self.assertEqual(copy[3:], ["--tag", f"{ACS_URI}:1.4.0", f"{ACS_SOURCE}@{ACS_DIGEST}"])

        values = self.change_set("rcs-platform")
        self.assertEqual(set(values), set(check_infra.load(str(PLATFORM))["Parameters"]))
        self.assertEqual({k: values[k] for k in example_values()}, example_values())
        self.assertEqual({k: values[k] for k in MANAGED}, {
            "EcrStackName": "rcs-platform-ecr", "ImageTag": TAG, "ImageDigest": PUSHED,
            "AcsImageTag": "1.4.0", "AcsImageDigest": ACS_DIGEST,
            "S3PrefixListId": "pl-0a1b2c3d", "DynamoDbPrefixListId": "pl-1a2b3c4d",
            "TemplateRevision": TAG, "PreviousImageTag": "none",
            "DeployPrincipalArn": "arn:aws:iam::123456789012:role/Deployer",
            "NlbReusedAddressA": "", "NlbReusedAddressB": ""})
        create = self.aws("cloudformation", "create-change-set", stack="rcs-platform")[0]
        self.assertEqual(create[create.index("--change-set-type") + 1], "CREATE")
        url = create[create.index("--template-url") + 1]
        self.assertTrue(url.startswith(f"https://{BUCKET}.s3.ap-northeast-2.amazonaws.com/rcs-platform/platform-"), url)
        self.assertIn("Key=rcs:stack,Value=rcs-platform", create)
        # Registry first, then both images, then the template and the stack.
        steps = [
            self.position("aws", "cloudformation", "execute-change-set", "--region", "ap-northeast-2", "--stack-name", "rcs-platform-ecr"),
            self.position("make"),
            self.position("docker", "push", f"{PLATFORM_URI}:{TAG}"),
            self.position("docker", "buildx", "imagetools", "create"),
            self.position("aws", "s3", "cp"),
            self.position("aws", "cloudformation", "execute-change-set", "--region", "ap-northeast-2", "--stack-name", "rcs-platform"),
        ]
        self.assertEqual(steps, sorted(steps))

    def test_replacements_are_shown_prominently(self):
        self.existing()
        self.state["images"] = {f"rcs-platform:{TAG}": PUSHED, "rcs-platform-acs:1.4.0": ACS_DIGEST}
        self.state["changes"]["rcs-platform"] = [["Modify", "SubscribersTable", "AWS::DynamoDB::Table", "True"],
                                                 ["Modify", "HssService", "AWS::ECS::Service", "False"],
                                                 ["Modify", "HssTaskDefinition", "AWS::ECS::TaskDefinition", "True"],
                                                 ["Remove", "OldTable", "AWS::DynamoDB::Table", ""],
                                                 ["Remove", "OldAlarm", "AWS::CloudWatch::Alarm", ""]]
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"!! Modify +SubscribersTable +AWS::DynamoDB::Table  REPLACED")
        self.assertRegex(result.stdout, r"!! Remove +OldTable")
        # A task definition is replaced on every image deployment, an alarm
        # holds nothing: listed, not marked.
        self.assertRegex(result.stdout, r"\n     Modify +HssTaskDefinition +AWS::ECS::TaskDefinition  REPLACED")
        self.assertRegex(result.stdout, r"\n     Remove +OldAlarm")
        self.assertIn("1 stateful resources replaced or possibly replaced, 1 removed", result.stdout)

    def test_an_image_deployment_replacing_only_task_definitions_has_no_warning(self):
        self.existing()
        self.state["images"] = {f"rcs-platform:{TAG}": PUSHED, "rcs-platform-acs:1.4.0": ACS_DIGEST}
        self.state["changes"]["rcs-platform"] = [["Modify", "HssTaskDefinition", "AWS::ECS::TaskDefinition", "True"]]
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("!!", result.stdout)

    def test_without_yes_and_without_a_terminal_nothing_runs(self):
        self.existing()
        self.state["images"] = {f"rcs-platform:{TAG}": PUSHED, "rcs-platform-acs:1.4.0": ACS_DIGEST}
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE))
        self.assertEqual(result.returncode, 1)
        self.assertIn("no terminal to confirm on", result.stderr)
        self.assertEqual(self.aws("cloudformation", "execute-change-set"), [])

    def test_a_plan_builds_and_pushes_nothing(self):
        self.existing()
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE), "--plan")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls("make") + self.calls("docker"), [])
        self.assertEqual(self.change_set("rcs-platform")["ImageDigest"], "sha256:" + "0" * 64)
        self.assertIn("nothing was built or pushed", result.stdout)

    def test_a_first_creation_over_the_elastic_ip_quota_is_refused(self):
        # The example has one NAT gateway and two new NLB addresses: 3.
        self.state["quotas"] = {"L-0263D0A3": "5.0"}
        self.state["addresses"] = {"eipalloc-1": "198.51.100.1", "eipalloc-2": "198.51.100.2", "eipalloc-3": "198.51.100.3"}
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 1)
        self.assertIn("allocates 3 Elastic IPs and the account holds 3, over the quota of 5.0", result.stderr)
        self.assertEqual(self.aws("cloudformation", "create-change-set"), [])
        # Reusing two retained addresses leaves one to allocate.
        path = self.config(replace={"NlbAllocationIdA": "eipalloc-1", "NlbAllocationIdB": "eipalloc-2"})
        result = self.run_script(DEPLOY, "--config", str(path), "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Elastic IPs: 1 to allocate, 3 held, quota 5.0", result.stdout)

    def test_a_different_template_revision_is_warned_about(self):
        self.existing(image_tag=TAG)
        self.state["outputs"]["rcs-platform"]["TemplateRevision"] = "v0.0.9"
        self.state["images"] = {f"rcs-platform:{TAG}": PUSHED, "rcs-platform-acs:1.4.0": ACS_DIGEST}
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"runs the template of v0.0.9; this run ships {TAG}'s", result.stderr)

    def test_a_first_image_has_nothing_to_roll_back_to(self):
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("there is no earlier one to roll back to", result.stdout)
        self.assertNotIn("--image-tag none", result.stdout)

    def test_a_plan_creates_change_sets_and_runs_none(self):
        self.existing()
        self.state["images"] = {f"rcs-platform:{TAG}": PUSHED, "rcs-platform-acs:1.4.0": ACS_DIGEST}
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE), "--plan")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.aws("cloudformation", "execute-change-set"), [])
        self.assertEqual(len(self.aws("cloudformation", "delete-change-set")), 2)
        self.assertIn("Plan only", result.stdout)

    def test_a_change_set_without_changes_is_not_run(self):
        self.existing()
        self.state["images"] = {f"rcs-platform:{TAG}": PUSHED, "rcs-platform-acs:1.4.0": ACS_DIGEST}
        self.state["empty"] = ["rcs-platform", "rcs-platform-ecr"]
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.aws("cloudformation", "execute-change-set"), [])
        self.assertEqual(result.stdout.count("no changes"), 2)

    def test_images_already_in_ecr_are_not_built_again(self):
        self.state["images"] = {f"rcs-platform:{TAG}": OLD, "rcs-platform-acs:1.4.0": ACS_DIGEST}
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls("make") + self.calls("docker"), [])
        self.assertEqual(self.change_set("rcs-platform")["ImageDigest"], OLD)

    def test_a_rollback_deploys_the_named_image_and_records_what_ran(self):
        self.existing(image_tag=TAG)
        self.state["describe"] = TAG
        self.state["images"] = {"rcs-platform:v0.0.9": OLD, "rcs-platform-acs:1.4.0": ACS_DIGEST}
        result = self.run_script(DEPLOY, *deploy("--skip-build", "--image-tag", "v0.0.9"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.aws("cloudformation", "create-change-set", stack="rcs-platform-ecr"), [])
        self.assertEqual(self.calls("make") + self.calls("docker"), [])
        values = self.change_set("rcs-platform")
        self.assertEqual((values["ImageTag"], values["ImageDigest"], values["PreviousImageTag"]), ("v0.0.9", OLD, TAG))
        self.assertIn("the template comes from v0.1.0-3-gabcdef0, the image from v0.0.9", result.stdout)
        self.assertIn(f"--skip-build --image-tag {TAG}", result.stdout)

    def test_a_configuration_change_keeps_the_recorded_rollback_target(self):
        self.existing(image_tag=TAG, previous="v0.0.8")
        self.state["images"] = {f"rcs-platform:{TAG}": PUSHED, "rcs-platform-acs:1.4.0": ACS_DIGEST}
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.change_set("rcs-platform")["PreviousImageTag"], "v0.0.8")

    def test_a_rollback_to_an_image_not_in_ecr_deploys_nothing(self):
        self.existing()
        self.state["images"] = {"rcs-platform-acs:1.4.0": ACS_DIGEST}
        result = self.run_script(DEPLOY, *deploy("--skip-build", "--image-tag", "v0.0.9"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("rcs-platform:v0.0.9 is not in ECR", result.stderr)
        self.assertEqual(self.aws("cloudformation", "create-change-set"), [])

    def test_a_rollback_needs_an_earlier_deployment(self):
        for status in (None, "REVIEW_IN_PROGRESS"):
            with self.subTest(status=status):
                self.state["stacks"] = {"rcs-platform-ecr": status} if status else {}
                result = self.run_script(DEPLOY, *deploy("--skip-build", "--image-tag", "v0.0.9"))
                self.assertEqual(result.returncode, 1)
                self.assertIn("rcs-platform-ecr does not exist", result.stderr)

    def test_a_copy_that_changed_the_bytes_deploys_nothing(self):
        self.state["copied_digest"] = "sha256:" + "ee" * 32
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 1)
        self.assertIn("after the copy, not " + ACS_DIGEST, result.stderr)
        self.assertEqual(self.aws("cloudformation", "create-change-set", stack="rcs-platform"), [])

    def test_the_pinned_acs_tag_must_hold_the_pinned_bytes(self):
        self.state["images"] = {"rcs-platform-acs:1.4.0": "sha256:" + "ff" * 32}
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 1)
        self.assertIn("not the pinned " + ACS_DIGEST, result.stderr)

    def test_the_acs_pin_is_the_local_stacks(self):
        script = DEPLOY.read_text()
        pinned = {name: re.search(rf'^{name}="([^"]+)"', script, re.M)[1] for name in ("ACS_VERSION", "ACS_DIGEST")}
        makefile = (ROOT / "Makefile").read_text()
        local = {name: re.search(rf"^{name}\s*\?=\s*(\S+)", makefile, re.M)[1] for name in pinned}
        self.assertEqual(local, pinned)

    def test_stacks_that_cannot_be_updated_are_refused_before_any_change(self):
        cases = [
            ("rcs-platform", "ROLLBACK_COMPLETE", "ROLLBACK_COMPLETE"),
            ("rcs-platform", "UPDATE_IN_PROGRESS", "wait for it to finish"),
            ("rcs-platform-ecr", "ROLLBACK_COMPLETE", "ROLLBACK_COMPLETE"),
            ("rcs-platform-ecr", "UPDATE_ROLLBACK_IN_PROGRESS", "wait for it to finish"),
            ("rcs-platform", "UPDATE_ROLLBACK_FAILED", "resolve that first"),
        ]
        for stack, status, message in cases:
            with self.subTest(stack=stack, status=status):
                self.state["stacks"] = {"rcs-platform-ecr": "CREATE_COMPLETE", "rcs-platform": "CREATE_COMPLETE", stack: status}
                result = self.run_script(DEPLOY, *deploy())
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stderr)
                self.assertIn(stack, result.stderr)
                self.assertEqual(self.aws("cloudformation", "create-change-set"), [])
                self.assertEqual(self.calls("make") + self.calls("docker"), [])

    def test_an_empty_review_stack_is_created_afresh(self):
        self.state["stacks"] = {"rcs-platform": "REVIEW_IN_PROGRESS"}
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 0, result.stderr)
        create = self.aws("cloudformation", "create-change-set", stack="rcs-platform")[0]
        self.assertEqual(create[create.index("--change-set-type") + 1], "CREATE")

    def test_names_retained_by_an_earlier_stack_are_found_first(self):
        self.state["taken"] = ["table rcs-platform-subscribers", "secret rcs-platform/hss/admin-token"]
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 1)
        self.assertIn("table rcs-platform-subscribers", result.stderr)
        self.assertIn("secret rcs-platform/hss/admin-token", result.stderr)
        self.assertEqual(self.aws("cloudformation", "create-change-set"), [])

    def test_a_retained_repository_is_found_before_the_registry_stack(self):
        self.state["taken"] = ["repository rcs-platform-acs"]
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 1)
        self.assertIn("repository rcs-platform-acs exists", result.stderr)

    def test_a_quota_too_small_for_a_rolling_update_is_refused(self):
        # The example: three services of 0.5 vCPU, one task each, two while
        # rolling (the relay runs too): 4 x 2 x 0.5 = 4 vCPU.
        self.state["quota"] = "3.0"
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 1)
        self.assertIn("needs up to 4.00 Fargate vCPU but the quota is 3.0", result.stderr)
        self.state["quota"] = None
        result = self.run_script(DEPLOY, *deploy())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cannot read the Fargate vCPU quota", result.stderr)

    def test_retained_nlb_addresses_are_passed_on(self):
        self.state["addresses"] = {"eipalloc-0a1": "198.51.100.7"}
        path = self.config(replace={"NlbAllocationIdA": "eipalloc-0a1"})
        result = self.run_script(DEPLOY, "--config", str(path), "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        values = self.change_set("rcs-platform")
        self.assertEqual((values["NlbAllocationIdA"], values["NlbReusedAddressA"], values["NlbReusedAddressB"]),
                         ("eipalloc-0a1", "198.51.100.7", ""))

    def test_an_unknown_allocation_stops_the_deployment(self):
        path = self.config(replace={"NlbAllocationIdB": "eipalloc-0ff"})
        result = self.run_script(DEPLOY, "--config", str(path), "--yes")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no Elastic IP eipalloc-0ff", result.stderr)
        self.assertEqual(self.aws("cloudformation", "create-change-set", stack="rcs-platform"), [])

    def test_values_reach_cloudformation_unchanged(self):
        value = 'a"b\\c,d=e'
        result = self.run_script(DEPLOY, "--config", str(self.config(replace={"AcsSmsOriginationIdentity": value})), "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.change_set("rcs-platform")["AcsSmsOriginationIdentity"], value)


class Teardown(Stubbed):
    """Deletion only after confirmation; retained resources are listed."""

    LB_ALB = "arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:loadbalancer/app/alb/1"
    LB_NLB = "arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:loadbalancer/net/nlb/2"

    def setUp(self):
        super().setUp()
        self.state["stacks"] = {"rcs-platform-ecr": "CREATE_COMPLETE", "rcs-platform": "UPDATE_COMPLETE"}
        self.state["resources"] = {
            "rcs-platform": [
                ["Alb", "AWS::ElasticLoadBalancingV2::LoadBalancer", self.LB_ALB, "CREATE_COMPLETE"],
                ["Nlb", "AWS::ElasticLoadBalancingV2::LoadBalancer", self.LB_NLB, "CREATE_COMPLETE"],
                ["SubscribersTable", "AWS::DynamoDB::Table", "rcs-platform-subscribers", "CREATE_COMPLETE"],
                ["HssKey", "AWS::KMS::Key", "key-example", "CREATE_COMPLETE"],
                ["HssAdminToken", "AWS::SecretsManager::Secret", "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:x", "CREATE_COMPLETE"],
            ],
            "rcs-platform-ecr": [
                ["PlatformRepository", "AWS::ECR::Repository", "rcs-platform", "CREATE_COMPLETE"],
                ["TemplateBucket", "AWS::S3::Bucket", BUCKET, "CREATE_COMPLETE"],
            ],
        }

    def deletes(self) -> list[str]:
        return [a[a.index("--stack-name") + 1] for a in self.aws("cloudformation", "delete-stack")]

    def protections(self) -> list[tuple[str, str]]:
        return [(a[a.index("--load-balancer-arn") + 1], a[a.index("--attributes") + 1].rsplit("=", 1)[1])
                for a in self.aws("elbv2")]

    def test_a_dry_run_calls_nothing_and_lists_what_the_template_retains(self):
        result = self.run_script(TEARDOWN, "--dry-run", "--with-registry")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])
        template = check_infra.load(str(PLATFORM))
        retained = [name for name, r in template["Resources"].items() if r.get("DeletionPolicy") == "Retain"]
        listed = result.stdout.split("would retain")[1].split("[2/2]")[0]
        self.assertEqual([line.strip() for line in listed.splitlines()[1:] if line.strip()], retained)

    def test_without_a_terminal_or_confirm_nothing_is_deleted(self):
        result = self.run_script(TEARDOWN)
        self.assertEqual(result.returncode, 1)
        self.assertIn("pass --confirm rcs-platform", result.stderr)
        self.assertEqual(self.deletes(), [])

    def test_a_wrong_name_deletes_nothing(self):
        result = self.run_script(TEARDOWN, "--confirm", "rcs-platform-prod")
        self.assertEqual(result.returncode, 1)
        self.assertIn("nothing was deleted", result.stderr)
        self.assertEqual(self.deletes(), [])

    def test_teardown_lifts_protection_deletes_and_lists_retained_data(self):
        result = self.run_script(TEARDOWN, "--confirm", "rcs-platform")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.protections(), [(self.LB_ALB, "false"), (self.LB_NLB, "false")])
        self.assertEqual(self.deletes(), ["rcs-platform"])
        self.assertEqual(len(self.aws("cloudformation", "get-template")), 1)
        self.assertIn("SubscribersTable  AWS::DynamoDB::Table  rcs-platform-subscribers", result.stdout)
        self.assertIn("HssKey  AWS::KMS::Key  key-example", result.stdout)
        self.assertNotIn("HssAdminToken", result.stdout)
        self.assertIn("kept (pass --with-registry", result.stdout)

    def test_the_retained_list_comes_from_the_deployed_template(self):
        older = self.dir / "older.yaml"
        older.write_text(PLATFORM.read_text().replace("  HssKey:\n    Type: AWS::KMS::Key\n    DeletionPolicy: Retain\n",
                                                      "  HssKey:\n    Type: AWS::KMS::Key\n"))
        self.state["deployed_templates"]["rcs-platform"] = str(older)
        result = self.run_script(TEARDOWN, "--confirm", "rcs-platform")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("HssKey", result.stdout)
        self.assertIn("SubscribersTable", result.stdout)

    def test_a_rolled_back_creation_with_deleted_load_balancers_is_deleted(self):
        self.state["stacks"]["rcs-platform"] = "ROLLBACK_COMPLETE"
        self.state["resources"]["rcs-platform"][0][3] = "DELETE_COMPLETE"
        self.state["resources"]["rcs-platform"][2][3] = "DELETE_COMPLETE"
        self.state["gone"] = [self.LB_NLB]
        result = self.run_script(TEARDOWN, "--confirm", "rcs-platform")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([arn for arn, _ in self.protections()], [self.LB_NLB])
        self.assertIn("no longer exists", result.stdout)
        self.assertEqual(self.deletes(), ["rcs-platform"])
        self.assertNotIn("rcs-platform-subscribers", result.stdout)

    def test_a_failed_deletion_puts_the_protection_back(self):
        self.state["delete_fails"] = True
        result = self.run_script(TEARDOWN, "--confirm", "rcs-platform")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.protections(), [(self.LB_ALB, "false"), (self.LB_NLB, "false"),
                                              (self.LB_ALB, "true"), (self.LB_NLB, "true")])
        self.assertIn("docs/runbook.md#teardown-failed", result.stderr)

    def test_an_empty_review_stack_is_deleted(self):
        self.state["stacks"]["rcs-platform"] = "REVIEW_IN_PROGRESS"
        self.state["resources"]["rcs-platform"] = []
        result = self.run_script(TEARDOWN, "--confirm", "rcs-platform")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.deletes(), ["rcs-platform"])
        self.assertEqual(self.aws("cloudformation", "get-template"), [])

    def test_a_stack_in_progress_is_left_alone(self):
        self.state["stacks"]["rcs-platform"] = "UPDATE_IN_PROGRESS"
        result = self.run_script(TEARDOWN, "--confirm", "rcs-platform")
        self.assertEqual(result.returncode, 1)
        self.assertIn("wait for it to finish", result.stderr)
        self.assertEqual(self.deletes(), [])

    def test_the_registry_goes_after_the_platform_with_its_bucket_emptied(self):
        result = self.run_script(TEARDOWN, "--confirm", "rcs-platform", "--with-registry")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.deletes(), ["rcs-platform", "rcs-platform-ecr"])
        self.assertLess(self.position("aws", "s3", "rm"),
                        self.position("aws", "cloudformation", "delete-stack", "--region", "ap-northeast-2",
                                      "--stack-name", "rcs-platform-ecr"))
        self.assertIn(f"s3://{BUCKET}", self.call("aws", "s3", "rm"))
        self.assertIn("PlatformRepository  AWS::ECR::Repository  rcs-platform", result.stdout)


class RotateToken(Stubbed):
    """The rotation order, the waits between steps, and stopping on failure."""

    def setUp(self):
        super().setUp()
        self.state["secrets"] = {"rcs-platform/hss/ft-server-token": "O" * 64,
                                 "rcs-platform/hss/ft-server-token-next": "S" * 64,
                                 "rcs-platform/hss/admin-token": "A" * 64,
                                 "rcs-platform/hss/admin-token-next": "B" * 64}

    def steps(self) -> list[str]:
        out = []
        for args in self.calls("aws"):
            if args[:2] == ["secretsmanager", "put-secret-value"]:
                out.append("put " + args[args.index("--secret-id") + 1].split("/", 1)[1])
            elif args[:2] == ["ecs", "update-service"]:
                out.append("restart " + args[args.index("--service") + 1])
        return out

    def test_a_rotation_runs_in_an_order_no_restart_can_break(self):
        result = self.run_script(ROTATE, "--token", "hss/ft-server-token")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.steps(), [
            "put hss/ft-server-token-next", "restart hss",
            "put hss/ft-server-token-next", "put hss/ft-server-token", "restart hss", "restart ft-server",
            "put hss/ft-server-token-next", "restart hss"])
        current = self.state["secrets"]["rcs-platform/hss/ft-server-token"]
        following = self.state["secrets"]["rcs-platform/hss/ft-server-token-next"]
        self.assertTrue(current.startswith("R1") and following.startswith("R2"))
        for value in ("O" * 64, current, following):
            self.assertNotIn(value, result.stdout + result.stderr)

    def test_each_step_waits_for_a_steady_service(self):
        self.state["rollouts"] = {"hss": ["2\tIN_PROGRESS\t3\t2", "1\tIN_PROGRESS\t2\t2", "1\tCOMPLETED\t1\t2"]}
        result = self.run_script(ROTATE, "--token", "hss/ft-server-token", "--step", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.aws("ecs", "describe-services")), 4)

    def test_a_failed_rollout_stops_the_rotation(self):
        self.state["rollouts"] = {"hss": ["1\tFAILED\t1\t2"]}
        result = self.run_script(ROTATE, "--token", "hss/ft-server-token")
        self.assertEqual(result.returncode, 1)
        self.assertIn("the rotation stops here", result.stderr)
        self.assertEqual(self.steps(), ["put hss/ft-server-token-next", "restart hss"])

    def test_a_service_that_never_settles_times_out(self):
        self.state["rollouts"] = {"hss": ["2\tIN_PROGRESS\t3\t2"] * 50}
        result = self.run_script(ROTATE, "--token", "hss/ft-server-token", env={"ROTATE_WAIT_SECONDS": "0"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("is not steady after 0 s", result.stderr)

    def test_a_caller_outside_the_stack_stops_after_step_two(self):
        result = self.run_script(ROTATE, "--token", "hss/admin-token")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.steps(), ["put hss/admin-token-next", "restart hss",
                                        "put hss/admin-token-next", "put hss/admin-token", "restart hss"])
        self.assertIn("--step 3", result.stdout)

    def test_step_two_refuses_equal_slots(self):
        self.state["secrets"]["rcs-platform/hss/ft-server-token-next"] = "O" * 64
        result = self.run_script(ROTATE, "--token", "hss/ft-server-token", "--step", "2")
        self.assertEqual(result.returncode, 1)
        self.assertIn("run step 1 first", result.stderr)
        self.assertEqual(self.steps(), [])

    def test_an_unknown_token_is_refused(self):
        result = self.run_script(ROTATE, "--token", "hss/other")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
