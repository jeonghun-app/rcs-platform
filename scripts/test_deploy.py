"""Tests of scripts/deploy.sh and scripts/teardown.sh against stand-ins.

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
EXAMPLE = ROOT / "infra" / "platform.example.params"
PLATFORM = ROOT / "infra" / "platform.yaml"
ECR = ROOT / "infra" / "ecr.yaml"

MANAGED = {"EcrStackName", "ImageTag", "AcsImageTag"}
REGISTRY = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com"
PLATFORM_URI = f"{REGISTRY}/rcs-platform"
ACS_URI = f"{REGISTRY}/rcs-platform-acs"
BUCKET = "rcs-platform-ecr-templatebucket-example"
ACS_DIGEST = "sha256:00956e9fe4d5865cf5e39292122ec1df78e34993f5c9d07928fff836af5f33b2"
ACS_SOURCE = "ghcr.io/jeonghun-app/auto-configuration-server"

STUB = r'''#!/usr/bin/env python3
import json, os, sys

tool = os.path.basename(sys.argv[0])
args = sys.argv[1:]
with open(os.environ["STUB_STATE"]) as f:
    state = json.load(f)
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps([tool, args, os.environ.get("DOCKER_DEFAULT_PLATFORM", "")]) + "\n")

def flag(name):
    return args[args.index(name) + 1] if name in args else None

def missing(message):
    sys.stderr.write(message + "\n")
    sys.exit(254)

def save():
    with open(os.environ["STUB_STATE"], "w") as f:
        json.dump(state, f)

if tool == "aws":
    command = args[:2]
    stack = flag("--stack-name")
    query = flag("--query") or ""
    if command == ["sts", "get-caller-identity"]:
        print("arn:aws:iam::123456789012:user/test")
    elif command == ["cloudformation", "describe-stacks"]:
        if stack not in state["stacks"]:
            missing(f"An error occurred (ValidationError): Stack with id {stack} does not exist")
        if "StackStatus" in query:
            print(state["stacks"][stack])
        elif "OutputKey==" in query:
            key = query.split("OutputKey=='")[1].split("'")[0]
            print(state["outputs"].get(key, "None"))
        else:
            print("outputs table")
    elif command == ["cloudformation", "deploy"]:
        state["stacks"].setdefault(stack, "CREATE_COMPLETE")
        save()
    elif command == ["cloudformation", "list-stack-resources"]:
        for line in state["resources"].get(stack, []):
            print("\t".join(line))
    elif command == ["ecr", "describe-images"]:
        image = flag("--repository-name") + ":" + flag("--image-ids").split("=", 1)[1]
        if image not in state["images"]:
            missing("An error occurred (ImageNotFoundException): no such image")
        print(state["images"][image])
    elif command == ["ecr", "get-login-password"]:
        print("password")
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
    state["images"][args[1].split("/", 1)[1]] = "sha256:1111"
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
            "stacks": {},
            "outputs": {
                "PlatformRepositoryUri": PLATFORM_URI,
                "AcsRepositoryUri": ACS_URI,
                "TemplateBucketName": BUCKET,
            },
            "resources": {},
            "images": {},
            "copied_digest": ACS_DIGEST,
            "dirty": "",
            "describe": "v0.1.0-3-gabcdef0",
        }
        self.env = {
            "PATH": f"{bin_dir}:/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.dir),
            "STUB_LOG": str(self.log),
            "STUB_STATE": str(self.state_file),
        }

    def tearDown(self):
        subprocess.run(["rm", "-rf", str(self.dir)], check=True)

    def run_script(self, script, *args, stdin=subprocess.DEVNULL) -> subprocess.CompletedProcess:
        self.state_file.write_text(json.dumps(self.state))
        return subprocess.run(["bash", str(script), *args], env=self.env, cwd=self.dir,
                              stdin=stdin, capture_output=True, text=True, timeout=60)

    def sequence(self) -> list[tuple[str, list[str]]]:
        return [(name, args) for name, args, _ in map(json.loads, self.log.read_text().splitlines())]

    def position(self, tool, *prefix) -> int:
        [index] = [i for i, (name, args) in enumerate(self.sequence())
                   if name == tool and args[:len(prefix)] == list(prefix)]
        return index

    def calls(self, tool=None) -> list[list[str]]:
        """Calls of a tool, without the check that docker has buildx."""
        found = [json.loads(line) for line in self.log.read_text().splitlines()]
        return [args for name, args, _ in found
                if (tool is None or name == tool) and args != ["buildx", "version"]]

    def call(self, tool, *prefix) -> list[str]:
        matches = [args for args in self.calls(tool) if args[:len(prefix)] == list(prefix)]
        self.assertEqual(len(matches), 1, f"{tool} {' '.join(prefix)}: {matches}")
        return matches[0]

    def deploys(self, stack) -> list[list[str]]:
        return [a for a in self.calls("aws")
                if a[:2] == ["cloudformation", "deploy"] and a[a.index("--stack-name") + 1] == stack]

    def config(self, *extra: str, drop: tuple[str, ...] = ()) -> pathlib.Path:
        lines = [line for line in EXAMPLE.read_text().splitlines()
                 if line.split("=", 1)[0] not in drop]
        path = self.dir / "test.params"
        path.write_text("\n".join(lines + list(extra)) + "\n")
        return path


def overrides(args: list[str]) -> dict[str, str]:
    values = args[args.index("--parameter-overrides") + 1:]
    pairs = [value.split("=", 1) for value in values]
    result = dict(pairs)
    assert len(result) == len(pairs), "a parameter is passed twice"
    return result


def example_values() -> dict[str, str]:
    values = {}
    for line in EXAMPLE.read_text().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


class DeployConfig(Stubbed):
    """The config names every parameter; mistakes stop before any call."""

    def test_the_example_names_every_parameter_the_script_does_not_set(self):
        parameters = set(check_infra.load(str(PLATFORM))["Parameters"])
        self.assertEqual(set(example_values()), parameters - MANAGED)

    def test_a_dry_run_calls_neither_aws_nor_docker(self):
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE), "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([a[2] for a in self.calls("git")], ["status", "describe"])
        self.assertEqual(self.calls("aws") + self.calls("docker") + self.calls("make"), [])
        self.assertIn("Dry run: nothing was built, pushed or deployed.", result.stdout)

    def test_a_dry_run_shows_every_parameter_once(self):
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE), "--dry-run")
        line = next(line for line in result.stdout.splitlines()
                    if "--stack-name rcs-platform " in line and "cloudformation deploy" in line)
        passed = overrides(line.split())
        parameters = set(check_infra.load(str(PLATFORM))["Parameters"])
        self.assertEqual(set(passed), parameters)
        self.assertEqual(passed["ImageTag"], "v0.1.0-3-gabcdef0")

    def test_a_missing_parameter_is_refused(self):
        result = self.run_script(DEPLOY, "--config", str(self.config(drop=("FtRealm",))), "--dry-run")
        self.assertEqual(result.returncode, 2)
        self.assertIn("FtRealm is missing", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_every_mistake_is_reported_at_once(self):
        path = self.config("Colour=blue", "Environment=prod", "ImageTag=v9", "WafRateLimit=\"2000\"",
                           "not a line")
        result = self.run_script(DEPLOY, "--config", str(path), "--dry-run")
        self.assertEqual(result.returncode, 2)
        for fragment in ("Colour is not a parameter", "Environment is set twice",
                         "ImageTag is set by deploy.sh", "WafRateLimit: values are literal",
                         "expected Key=Value"):
            self.assertIn(fragment, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_an_image_tag_without_skip_build_is_refused(self):
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE), "--image-tag", "v1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("use them with --skip-build", result.stderr)

    def test_a_dirty_tree_is_not_built(self):
        self.state["dirty"] = " M internal/hss/hss.go\n"
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE))
        self.assertEqual(result.returncode, 1)
        self.assertIn("uncommitted or untracked files", result.stderr)
        self.assertEqual(self.calls("aws"), [])


class Deploy(Stubbed):
    """A deployment against the stubs, from an empty account to a rollback."""

    def test_a_first_deployment_builds_pushes_and_passes_every_parameter(self):
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE))
        self.assertEqual(result.returncode, 0, result.stderr)

        [ecr] = self.deploys("rcs-platform-ecr")
        self.assertEqual(overrides(ecr), {
            "PlatformRepositoryName": "rcs-platform", "AcsRepositoryName": "rcs-platform-acs",
            "UntaggedImageExpiryDays": "7", "MaxTaggedImages": "30"})
        self.assertEqual(set(overrides(ecr)), set(check_infra.load(str(ECR))["Parameters"]))

        make = self.call("make")
        self.assertIn(f"IMAGE={PLATFORM_URI}", make)
        self.assertIn("VERSION=v0.1.0-3-gabcdef0", make)
        [[_, _, platform]] = [c for c in map(json.loads, self.log.read_text().splitlines()) if c[0] == "make"]
        self.assertEqual(platform, "linux/amd64")
        # acs is copied by digest from its release, not built.
        copy = self.call("docker", "buildx", "imagetools", "create")
        self.assertEqual(copy[3:], ["--tag", f"{ACS_URI}:1.4.0", f"{ACS_SOURCE}@{ACS_DIGEST}"])
        self.assertEqual([a[1] for a in self.calls("docker") if a[0] == "push"],
                         [f"{PLATFORM_URI}:v0.1.0-3-gabcdef0"])

        [platform_deploy] = self.deploys("rcs-platform")
        self.assertEqual(platform_deploy[platform_deploy.index("--s3-bucket") + 1], BUCKET)
        expected = example_values() | {
            "EcrStackName": "rcs-platform-ecr", "ImageTag": "v0.1.0-3-gabcdef0", "AcsImageTag": "1.4.0"}
        self.assertEqual(overrides(platform_deploy), expected)
        # Registry first, then both images, then the platform stack.
        steps = [
            self.position("aws", "cloudformation", "deploy", "--region", "ap-northeast-2", "--stack-name", "rcs-platform-ecr"),
            self.position("make"),
            self.position("docker", "push", f"{PLATFORM_URI}:v0.1.0-3-gabcdef0"),
            self.position("docker", "buildx", "imagetools", "create"),
            self.position("aws", "cloudformation", "deploy", "--region", "ap-northeast-2", "--stack-name", "rcs-platform"),
        ]
        self.assertEqual(steps, sorted(steps))

    def test_images_already_in_ecr_are_not_built_again(self):
        self.state["images"] = {"rcs-platform:v0.1.0-3-gabcdef0": "sha256:1111", "rcs-platform-acs:1.4.0": ACS_DIGEST}
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls("make") + self.calls("docker"), [])
        self.assertEqual(len(self.deploys("rcs-platform")), 1)

    def test_a_rollback_deploys_the_named_images_and_changes_nothing_else(self):
        self.state["stacks"] = {"rcs-platform-ecr": "UPDATE_COMPLETE", "rcs-platform": "UPDATE_COMPLETE"}
        self.state["images"] = {"rcs-platform:v0.0.9": "sha256:1111", "rcs-platform-acs:1.4.0": ACS_DIGEST}
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE), "--skip-build", "--image-tag", "v0.0.9")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.deploys("rcs-platform-ecr"), [])
        self.assertEqual(self.calls("make") + self.calls("docker") + self.calls("git"), [])
        [platform_deploy] = self.deploys("rcs-platform")
        self.assertEqual(overrides(platform_deploy)["ImageTag"], "v0.0.9")
        self.assertEqual(overrides(platform_deploy)["Environment"], "dev")

    def test_a_rollback_to_an_image_not_in_ecr_deploys_nothing(self):
        self.state["stacks"] = {"rcs-platform-ecr": "UPDATE_COMPLETE", "rcs-platform": "UPDATE_COMPLETE"}
        self.state["images"] = {"rcs-platform-acs:1.4.0": ACS_DIGEST}
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE), "--skip-build", "--image-tag", "v0.0.9")
        self.assertEqual(result.returncode, 1)
        self.assertIn("rcs-platform:v0.0.9 is not in ECR", result.stderr)
        self.assertEqual(self.deploys("rcs-platform"), [])

    def test_a_rollback_needs_an_earlier_deployment(self):
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE), "--skip-build", "--image-tag", "v0.0.9")
        self.assertEqual(result.returncode, 1)
        self.assertIn("rcs-platform-ecr does not exist", result.stderr)

    def test_a_copy_that_changed_the_bytes_deploys_nothing(self):
        self.state["copied_digest"] = "sha256:2222"
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE))
        self.assertEqual(result.returncode, 1)
        self.assertIn("after the copy, not " + ACS_DIGEST, result.stderr)
        self.assertEqual(self.deploys("rcs-platform"), [])

    def test_the_pinned_acs_tag_must_hold_the_pinned_bytes(self):
        self.state["images"] = {"rcs-platform-acs:1.4.0": "sha256:3333"}
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE))
        self.assertEqual(result.returncode, 1)
        self.assertIn("not the pinned " + ACS_DIGEST, result.stderr)
        self.assertEqual(self.deploys("rcs-platform"), [])

    def test_the_acs_pin_is_the_local_stacks(self):
        script = DEPLOY.read_text()
        pinned = {name: re.search(rf'^{name}="([^"]+)"', script, re.M)[1] for name in ("ACS_VERSION", "ACS_DIGEST")}
        self.assertEqual(pinned, {"ACS_VERSION": "1.4.0", "ACS_DIGEST": ACS_DIGEST})
        makefile = (ROOT / "Makefile").read_text()
        local = {name: m[1] for name in pinned if (m := re.search(rf"^{name}\s*\?=\s*(\S+)", makefile, re.M))}
        if not local:
            self.skipTest("the Makefile pins no acs image yet (#83)")
        self.assertEqual(local, pinned)

    def test_a_stack_whose_creation_rolled_back_is_refused_before_any_change(self):
        self.state["stacks"] = {"rcs-platform-ecr": "CREATE_COMPLETE", "rcs-platform": "ROLLBACK_COMPLETE"}
        result = self.run_script(DEPLOY, "--config", str(EXAMPLE))
        self.assertEqual(result.returncode, 1)
        self.assertIn("ROLLBACK_COMPLETE", result.stderr)
        self.assertEqual([a for a in self.calls("aws") if a[:2] == ["cloudformation", "deploy"]], [])
        self.assertEqual(self.calls("make") + self.calls("docker"), [])


class Teardown(Stubbed):
    """Deletion only after confirmation; retained resources are listed."""

    def setUp(self):
        super().setUp()
        self.state["stacks"] = {"rcs-platform-ecr": "CREATE_COMPLETE", "rcs-platform": "UPDATE_COMPLETE"}
        self.state["resources"] = {
            "rcs-platform": [
                ["Alb", "AWS::ElasticLoadBalancingV2::LoadBalancer", "arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:loadbalancer/app/alb/1"],
                ["Nlb", "AWS::ElasticLoadBalancingV2::LoadBalancer", "arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:loadbalancer/net/nlb/2"],
                ["SubscribersTable", "AWS::DynamoDB::Table", "rcs-platform-subscribers"],
                ["HssKey", "AWS::KMS::Key", "key-example"],
                ["HssAdminToken", "AWS::SecretsManager::Secret", "arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:x"],
            ],
            "rcs-platform-ecr": [
                ["PlatformRepository", "AWS::ECR::Repository", "rcs-platform"],
                ["TemplateBucket", "AWS::S3::Bucket", BUCKET],
            ],
        }

    def deletes(self) -> list[str]:
        return [a[a.index("--stack-name") + 1] for a in self.calls("aws") if a[:2] == ["cloudformation", "delete-stack"]]

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
        lifted = [a[a.index("--load-balancer-arn") + 1] for a in self.calls("aws") if a[:1] == ["elbv2"]]
        self.assertEqual(len(lifted), 2)
        self.assertEqual(self.deletes(), ["rcs-platform"])
        self.assertIn("SubscribersTable  AWS::DynamoDB::Table  rcs-platform-subscribers", result.stdout)
        self.assertIn("HssKey  AWS::KMS::Key  key-example", result.stdout)
        self.assertNotIn("HssAdminToken", result.stdout)
        self.assertIn("kept (pass --with-registry", result.stdout)

    def test_the_registry_goes_after_the_platform_with_its_bucket_emptied(self):
        result = self.run_script(TEARDOWN, "--confirm", "rcs-platform", "--with-registry")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.deletes(), ["rcs-platform", "rcs-platform-ecr"])
        self.assertLess(self.position("aws", "s3", "rm"),
                        self.position("aws", "cloudformation", "delete-stack", "--region", "ap-northeast-2",
                                      "--stack-name", "rcs-platform-ecr"))
        self.assertIn(f"s3://{BUCKET}", self.call("aws", "s3", "rm"))
        self.assertIn("PlatformRepository  AWS::ECR::Repository  rcs-platform", result.stdout)


if __name__ == "__main__":
    unittest.main()
