"""Policy checks on infra/platform.yaml that cfn-lint cannot express.

cfn-lint proves a template is valid CloudFormation; this proves it is the
platform the ADRs describe:

* the security group matrix of ADR 0007 §2, exactly: private groups admit only
  the listed source groups on the listed ports, never an address range; every
  group replaces the default allow-all egress; egress mirrors the matrix plus
  HTTPS for the AWS APIs;
* plain SIP and MSRP listeners, and their public ports, exist in dev only
  (ADR 0003);
* every NLB target group has Proxy Protocol v2 on and keeps connections at
  deregistration (ADR 0003), and every
  internet-facing ALB has an AWS WAF web ACL (ft-server and acs limit per task
  only, docs/ft-server.md);
* every task definition has a read-only root file system, drops all Linux
  capabilities and is not privileged, and no service enables ECS Exec
  (ADR 0007 §9);
* every DynamoDB table has point-in-time recovery (ADR 0003);
* no task role can read a secret: secrets reach tasks through the execution
  role only (ADR 0007 §4);
* tables holding capabilities are read only by their own service's task
  role, and nothing may export them: msrp-bindings holds rcs-as session ids
  (threat model T3, #54); a wildcard ARN, or one naming the table, counts;
* every task role is granted each action its service's code calls
  (infra/task-role-actions.yaml).

Runs in the infra tools image (deploy/infra-tools.Dockerfile), which provides
cfn-lint's CloudFormation YAML decoder. Usage: check_infra.py TEMPLATE...
Exit status 1 lists every problem.
"""

from __future__ import annotations

import fnmatch
import pathlib
import re
import sys
from dataclasses import dataclass

# (destination group, port) -> source groups. ADR 0007 §2; ports as listed at
# the security groups in infra/platform.yaml.
EXPECTED_INGRESS: dict[tuple[str, int], set[str]] = {
    ("PcscfSecurityGroup", 5061): {"NlbSecurityGroup"},
    ("PcscfSecurityGroup", 5070): {"ScscfSecurityGroup"},
    ("IcscfSecurityGroup", 5060): {"PcscfSecurityGroup", "RcsAsSecurityGroup", "ScscfSecurityGroup"},
    ("ScscfSecurityGroup", 5060): {"PcscfSecurityGroup", "RcsAsSecurityGroup", "IcscfSecurityGroup"},
    ("RcsAsSecurityGroup", 5060): {"ScscfSecurityGroup", "IcscfSecurityGroup", "RcsAsSecurityGroup"},
    ("RcsAsSecurityGroup", 2855): {"MsrpRelaySecurityGroup"},
    ("HssSecurityGroup", 3868): {"IcscfSecurityGroup", "ScscfSecurityGroup"},
    ("HssSecurityGroup", 8081): {"FtServerSecurityGroup", "AcsSecurityGroup", "OperatorSecurityGroup"},
    ("MsrpRelaySecurityGroup", 2855): {"NlbSecurityGroup"},
    ("MsrpRelaySecurityGroup", 8082): {"PcscfSecurityGroup"},
    ("FtServerSecurityGroup", 8081): {"AlbSecurityGroup"},
    ("FtServerSecurityGroup", 8080): {"AlbSecurityGroup"},
    ("AcsSecurityGroup", 8080): {"AlbSecurityGroup"},
}

# Internet-facing groups and the TCP ports they may admit from an address
# range (the PublicIngressCidr parameter).
PUBLIC_PORTS: dict[str, set[int]] = {
    "NlbSecurityGroup": {5060, 5061, 2855, 2856},
    "AlbSecurityGroup": {80, 443},
}

# What a group may send to an address range: HTTPS for the AWS APIs (through
# the NAT gateways and the gateway endpoints), or nothing, written as the
# unroutable entry that replaces the default allow-all.
ALLOWED_CIDR_EGRESS = {("tcp", 443, 443, "0.0.0.0/0"), ("icmp", -1, -1, "127.0.0.1/32")}

NETWORK_PROTOCOLS = {"TCP", "TLS", "UDP", "TCP_UDP"}


@dataclass(frozen=True)
class Rule:
    """One security group rule, normalised from either form of declaring it."""

    group: str
    protocol: str
    from_port: int
    to_port: int
    peer_group: str | None
    cidr: str | None
    other: str | None  # prefix lists, IPv6 ranges: never expected


def load(path: str) -> dict:
    """Decode a template, intrinsic-function tags included."""
    from cfnlint.decode import decode  # provided by the infra tools image

    template, errors = decode(path)
    if errors:
        raise SystemExit(f"{path}: cannot decode: {errors}")
    return template


def logical_id(value) -> str | None:
    """The logical id named by a Ref or a GetAtt, or None."""
    if isinstance(value, dict):
        if "Ref" in value:
            return value["Ref"]
        if "Fn::GetAtt" in value:
            target = value["Fn::GetAtt"]
            return target[0] if isinstance(target, list) else str(target).split(".")[0]
    return None


def resources(template: dict, kind: str) -> dict[str, dict]:
    return {name: r for name, r in template.get("Resources", {}).items() if r.get("Type") == kind}


def _rule(group: str, props: dict, peer_key: str) -> Rule:
    cidr = props.get("CidrIp")
    if isinstance(cidr, dict):
        # A parameter such as PublicIngressCidr: an address range all the same.
        cidr = "ref:" + (logical_id(cidr) or "?")
    other = None
    for key in ("CidrIpv6", "SourcePrefixListId", "DestinationPrefixListId"):
        if key in props:
            other = key
    return Rule(
        group=group,
        protocol=str(props.get("IpProtocol")),
        from_port=int(props.get("FromPort", -1)),
        to_port=int(props.get("ToPort", -1)),
        peer_group=logical_id(props.get(peer_key)),
        cidr=cidr,
        other=other,
    )


def inline_rules(items: list) -> list[tuple[dict, str | None]]:
    """Inline rules with the condition each depends on.

    A rule may be wrapped in Fn::If [Condition, rule, AWS::NoValue]; both
    branches are rules the template can produce, so both are checked.
    """
    found = []
    for item in items:
        if isinstance(item, dict) and "Fn::If" in item:
            condition, *branches = item["Fn::If"]
            found += [(b, condition) for b in branches if isinstance(b, dict) and "Ref" not in b]
        else:
            found.append((item, None))
    return found


def collect(template: dict) -> tuple[list[Rule], list[Rule]]:
    """Every ingress and egress rule, inline or separate."""
    ingress, egress = [], []
    for name, sg in resources(template, "AWS::EC2::SecurityGroup").items():
        props = sg.get("Properties", {})
        ingress += [_rule(name, p, "SourceSecurityGroupId") for p, _ in inline_rules(props.get("SecurityGroupIngress", []))]
        egress += [_rule(name, p, "DestinationSecurityGroupId") for p, _ in inline_rules(props.get("SecurityGroupEgress", []))]
    for r in resources(template, "AWS::EC2::SecurityGroupIngress").values():
        props = r.get("Properties", {})
        ingress.append(_rule(logical_id(props.get("GroupId")) or "?", props, "SourceSecurityGroupId"))
    for r in resources(template, "AWS::EC2::SecurityGroupEgress").values():
        props = r.get("Properties", {})
        egress.append(_rule(logical_id(props.get("GroupId")) or "?", props, "DestinationSecurityGroupId"))
    return ingress, egress


def check_security_groups(template: dict) -> list[str]:
    problems = []
    groups = resources(template, "AWS::EC2::SecurityGroup")
    for name, sg in groups.items():
        if not sg.get("Properties", {}).get("SecurityGroupEgress"):
            problems.append(f"{name}: no inline egress rule, so the default allow-all egress stays")
    ingress, egress = collect(template)

    seen: dict[tuple[str, int], set[str]] = {}
    for r in ingress:
        where = f"{r.group} ingress {r.protocol} {r.from_port}-{r.to_port}"
        if r.protocol != "tcp" or r.from_port != r.to_port:
            problems.append(f"{where}: rules are single TCP ports")
            continue
        if r.other:
            problems.append(f"{where}: {r.other} is not part of the matrix")
        elif r.cidr is not None:
            if r.from_port not in PUBLIC_PORTS.get(r.group, set()):
                problems.append(f"{where}: admits an address range ({r.cidr}); private groups admit only groups")
        elif r.group in PUBLIC_PORTS:
            problems.append(f"{where}: an internet-facing group admits only clients")
        else:
            seen.setdefault((r.group, r.from_port), set()).add(r.peer_group or "?")

    for key in sorted(set(seen) | set(EXPECTED_INGRESS)):
        got, want = seen.get(key, set()), EXPECTED_INGRESS.get(key, set())
        for source in sorted(got - want):
            problems.append(f"{key[0]} port {key[1]}: {source} is not in the ADR 0007 matrix")
        for source in sorted(want - got):
            problems.append(f"{key[0]} port {key[1]}: {source} is missing (ADR 0007 matrix)")

    expected_egress = {(src, dst, port) for (dst, port), srcs in EXPECTED_INGRESS.items() for src in srcs}
    seen_egress = set()
    for r in egress:
        where = f"{r.group} egress {r.protocol} {r.from_port}-{r.to_port}"
        if r.other:
            problems.append(f"{where}: {r.other} egress is not expected")
        elif r.cidr is not None:
            if (r.protocol, r.from_port, r.to_port, r.cidr) not in ALLOWED_CIDR_EGRESS:
                problems.append(f"{where}: to {r.cidr}; only HTTPS for the AWS APIs may leave to an address range")
            elif r.group in PUBLIC_PORTS and r.protocol != "icmp":
                # A load balancer sends only to its targets.
                problems.append(f"{where}: an internet-facing group sends to an address range")
        elif r.protocol != "tcp" or r.from_port != r.to_port:
            problems.append(f"{where}: rules are single TCP ports")
        else:
            seen_egress.add((r.group, r.peer_group or "?", r.from_port))
    for src, dst, port in sorted(seen_egress - expected_egress):
        problems.append(f"{src} egress to {dst} port {port} has no matching matrix entry")
    for src, dst, port in sorted(expected_egress - seen_egress):
        problems.append(f"{src} egress to {dst} port {port} is missing: the matrix entry cannot be used")
    return problems


def check_target_groups(template: dict) -> list[str]:
    problems = []
    for name, tg in resources(template, "AWS::ElasticLoadBalancingV2::TargetGroup").items():
        props = tg.get("Properties", {})
        if props.get("Protocol") not in NETWORK_PROTOCOLS:
            continue
        attrs = {a.get("Key"): str(a.get("Value")).lower() for a in props.get("TargetGroupAttributes", [])}
        if attrs.get("proxy_protocol_v2.enabled") != "true":
            problems.append(f"{name}: NLB target group without Proxy Protocol v2 (ADR 0003)")
        if attrs.get("preserve_client_ip.enabled") != "false":
            # With client addresses preserved, targets would have to admit the
            # clients' address ranges, outside the matrix.
            problems.append(f"{name}: NLB target group must not preserve client addresses (PPv2 carries them)")
        if attrs.get("deregistration_delay.connection_termination.enabled") != "false":
            # On, the NLB resets every connection of a deregistered target at
            # once, ahead of the service's staggered drain (ADR 0003).
            problems.append(f"{name}: NLB target group must keep connections at deregistration (connection_termination false)")
    return problems


# Plain SIP and MSRP on the NLB: ADR 0003 refuses them in staging and prod.
PLAIN_PORTS = {5060, 2855}
PLAIN_PROTOCOLS = {"TCP", "UDP", "TCP_UDP"}


def dev_only(template: dict, condition: str | None) -> bool:
    """Whether a condition holds only in dev: IsDev, or an And that has it."""
    if condition == "IsDev":
        return True
    definition = template.get("Conditions", {}).get(condition) if condition else None
    return isinstance(definition, dict) and {"Condition": "IsDev"} in definition.get("Fn::And", [])


def check_plain_listeners(template: dict) -> list[str]:
    problems = []
    for name, listener in resources(template, "AWS::ElasticLoadBalancingV2::Listener").items():
        protocol = listener.get("Properties", {}).get("Protocol")
        if protocol in PLAIN_PROTOCOLS and not dev_only(template, listener.get("Condition")):
            problems.append(f"{name}: a plain {protocol} listener outside dev (ADR 0003)")
    nlb = resources(template, "AWS::EC2::SecurityGroup").get("NlbSecurityGroup", {})
    for rule, condition in inline_rules(nlb.get("Properties", {}).get("SecurityGroupIngress", [])):
        if rule.get("FromPort") in PLAIN_PORTS and not dev_only(template, condition):
            problems.append(f"NlbSecurityGroup: plain port {rule.get('FromPort')} open outside dev (ADR 0003)")
    return problems


# Listener ports per load balancer: what clients may use (ADR 0003).
LISTENER_PORTS = {"Nlb": {5060, 5061, 2855, 2856}, "Alb": {80, 443}}


def check_load_balancers(template: dict) -> list[str]:
    """Only Nlb and Alb face the internet, on their listed ports only."""
    problems = []
    lbs = resources(template, "AWS::ElasticLoadBalancingV2::LoadBalancer")
    for name, lb in lbs.items():
        if lb.get("Properties", {}).get("Scheme", "internet-facing") != "internal" and name not in LISTENER_PORTS:
            problems.append(f"{name}: internet-facing; only {', '.join(sorted(LISTENER_PORTS))} may be")
    for name, listener in resources(template, "AWS::ElasticLoadBalancingV2::Listener").items():
        props = listener.get("Properties", {})
        lb = logical_id(props.get("LoadBalancerArn"))
        if lb in LISTENER_PORTS and props.get("Port") not in LISTENER_PORTS[lb]:
            problems.append(f"{name}: port {props.get('Port')} on {lb} is not a client port")
    return problems


def check_waf(template: dict) -> list[str]:
    protected = {
        logical_id(a.get("Properties", {}).get("ResourceArn"))
        for a in resources(template, "AWS::WAFv2::WebACLAssociation").values()
    }
    problems = []
    for name, lb in resources(template, "AWS::ElasticLoadBalancingV2::LoadBalancer").items():
        props = lb.get("Properties", {})
        if props.get("Type", "application") == "application" and props.get("Scheme") != "internal" and name not in protected:
            problems.append(f"{name}: internet-facing ALB without an AWS WAF web ACL")
    for name, acl in resources(template, "AWS::WAFv2::WebACL").items():
        rules = acl.get("Properties", {}).get("Rules", [])
        if not any("RateBasedStatement" in r.get("Statement", {}) for r in rules if isinstance(r, dict)):
            problems.append(f"{name}: no rate-based rule; per-task limits do not hold one client back across tasks")
    return problems


def is_true(value) -> bool:
    """CloudFormation accepts booleans as strings; 'true' is as true as True."""
    return value is True or str(value).strip().lower() == "true"


def check_tasks(template: dict) -> list[str]:
    problems = []
    for name, td in resources(template, "AWS::ECS::TaskDefinition").items():
        for c in td.get("Properties", {}).get("ContainerDefinitions", []):
            where = f"{name}/{c.get('Name', '?')}"
            if not is_true(c.get("ReadonlyRootFilesystem")):
                problems.append(f"{where}: root file system is not read-only")
            if is_true(c.get("Privileged")):
                problems.append(f"{where}: privileged")
            drop = c.get("LinuxParameters", {}).get("Capabilities", {}).get("Drop", [])
            if "ALL" not in drop:
                problems.append(f"{where}: does not drop all Linux capabilities")
            if c.get("LinuxParameters", {}).get("Capabilities", {}).get("Add"):
                problems.append(f"{where}: adds Linux capabilities")
    for name, svc in resources(template, "AWS::ECS::Service").items():
        if is_true(svc.get("Properties", {}).get("EnableExecuteCommand")):
            problems.append(f"{name}: ECS Exec is enabled")
    return problems


def check_tables(template: dict) -> list[str]:
    problems = []
    for name, table in resources(template, "AWS::DynamoDB::Table").items():
        pitr = table.get("Properties", {}).get("PointInTimeRecoverySpecification", {})
        if not is_true(pitr.get("PointInTimeRecoveryEnabled")):
            problems.append(f"{name}: point-in-time recovery is off")
        if not is_true(table.get("Properties", {}).get("SSESpecification", {}).get("SSEEnabled")):
            problems.append(f"{name}: SSE with a KMS key is not on (SSESpecification.SSEEnabled)")
    return problems


def check_buckets(template: dict) -> list[str]:
    """Encrypted, all public access blocked, and TLS only (a Deny on
    aws:SecureTransport false in the bucket's policy)."""
    problems = []
    policies = {}
    for policy in resources(template, "AWS::S3::BucketPolicy").values():
        props = policy.get("Properties", {})
        policies[logical_id(props.get("Bucket"))] = props.get("PolicyDocument", {})
    for name, bucket in resources(template, "AWS::S3::Bucket").items():
        props = bucket.get("Properties", {})
        if not props.get("BucketEncryption", {}).get("ServerSideEncryptionConfiguration"):
            problems.append(f"{name}: no default encryption")
        block = props.get("PublicAccessBlockConfiguration", {})
        for key in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"):
            if not is_true(block.get(key)):
                problems.append(f"{name}: {key} is not on")
        tls = any(st.get("Effect") == "Deny"
                  and str(st.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport")).lower() == "false"
                  for st in policies.get(name, {}).get("Statement", []))
        if not tls:
            problems.append(f"{name}: its policy does not refuse requests without TLS")
    return problems


def _actions(statement: dict) -> list[str]:
    actions = statement.get("Action", [])
    return [actions] if isinstance(actions, str) else list(actions)


# Actions that hand out a secret's value; a granted pattern such as
# secretsmanager:* or ssm:Get* covers them too.
SECRET_ACTIONS = (
    "secretsmanager:getsecretvalue",
    "secretsmanager:batchgetsecretvalue",
    "ssm:getparameter",
    "ssm:getparameters",
    "ssm:getparametersbypath",
)


def covers(granted: list[str], wanted) -> bool:
    """Whether granted action patterns allow any of the wanted actions."""
    wanted = [wanted] if isinstance(wanted, str) else wanted
    return any(fnmatch.fnmatchcase(w, g.lower()) for g in granted if isinstance(g, str) for w in wanted)


def _reads_secrets(document: dict) -> bool:
    for statement in document.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        if "NotAction" in statement or covers(_actions(statement), SECRET_ACTIONS):
            return True
    return False


def _policies(role: dict) -> list[dict]:
    """A role's inline policies, both branches of an Fn::If included."""
    found = []
    for policy in role.get("Properties", {}).get("Policies", []):
        if isinstance(policy, dict) and "Fn::If" in policy:
            found += [b for b in policy["Fn::If"][1:] if isinstance(b, dict) and "PolicyDocument" in b]
        elif isinstance(policy, dict):
            found.append(policy)
    return found


def task_roles(template: dict) -> set[str]:
    """Roles a task's code runs as: every role ECS tasks may assume that is no
    task definition's execution role, so a role created before its service
    (and its task definition) is covered too."""
    tds = resources(template, "AWS::ECS::TaskDefinition").values()
    execution = {logical_id(td.get("Properties", {}).get("ExecutionRoleArn")) for td in tds}
    named = {logical_id(td.get("Properties", {}).get("TaskRoleArn")) for td in tds}
    assumed = set()
    for name, role in resources(template, "AWS::IAM::Role").items():
        trust = role.get("Properties", {}).get("AssumeRolePolicyDocument", {})
        for st in trust.get("Statement", []):
            services = st.get("Principal", {}).get("Service", [])
            if "ecs-tasks.amazonaws.com" in ([services] if isinstance(services, str) else services):
                assumed.add(name)
    return ((assumed - execution) | named) - {None}


def check_secret_access(template: dict) -> list[str]:
    roles_of_tasks = task_roles(template)
    problems = []
    for name, td in resources(template, "AWS::ECS::TaskDefinition").items():
        props = td.get("Properties", {})
        task = logical_id(props.get("TaskRoleArn"))
        if task is not None and task == logical_id(props.get("ExecutionRoleArn")):
            problems.append(f"{name}: the task role is also the execution role, so the task can read its secrets")
    roles = resources(template, "AWS::IAM::Role")
    for name in sorted(roles_of_tasks):
        role = roles.get(name, {})
        for policy in _policies(role):
            if _reads_secrets(policy.get("PolicyDocument", {})):
                problems.append(f"{name}: a task role may read secrets (only execution roles may)")
        if role.get("Properties", {}).get("ManagedPolicyArns"):
            problems.append(f"{name}: a task role has managed policies, which this check cannot see into")
    for kind in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::RolePolicy"):
        for name, policy in resources(template, kind).items():
            props = policy.get("Properties", {})
            attached = {logical_id(r) for r in props.get("Roles", [])} | {logical_id(props.get("RoleName"))}
            if attached & roles_of_tasks and _reads_secrets(props.get("PolicyDocument", {})):
                problems.append(f"{name}: lets a task role read secrets (only execution roles may)")
    # A secret's own resource policy could hand it to a task role, or anyone.
    for name, policy in resources(template, "AWS::SecretsManager::ResourcePolicy").items():
        for st in policy.get("Properties", {}).get("ResourcePolicy", {}).get("Statement", []):
            if st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal", {})
            names = _names(principal.get("AWS") if isinstance(principal, dict) else principal)
            if "*" in names or names & roles_of_tasks or principal == "*":
                problems.append(f"{name}: a secret resource policy lets a task role or anyone read it")

    # Each execution role reads exactly the secrets its task definition
    # injects (ADR 0007 §4), never a wildcard.
    allowed: dict[str, set[str]] = {}
    for td in resources(template, "AWS::ECS::TaskDefinition").values():
        props = td.get("Properties", {})
        role = logical_id(props.get("ExecutionRoleArn"))
        refs = {logical_id(s.get("ValueFrom")) for c in props.get("ContainerDefinitions", []) for s in c.get("Secrets", [])}
        allowed.setdefault(role, set()).update(refs - {None})
    for role, secrets in sorted(allowed.items()):
        for policy in _policies(roles.get(role, {})):
            for st in policy.get("PolicyDocument", {}).get("Statement", []):
                if st.get("Effect") == "Allow" and covers(_actions(st), SECRET_ACTIONS):
                    targets = _names(st.get("Resource"))
                    if "*" in targets or not targets <= secrets:
                        extra = sorted(targets - secrets) or ["*"]
                        problems.append(f"{role}: may read {', '.join(extra)}, which its task definition does not inject")
    return problems


# Tables whose items are capabilities, and the only roles that may read them.
TABLE_READERS: dict[str, set[str]] = {"MsrpBindingsTable": {"MsrpRelayTaskRole"}}

READ_ACTIONS = {
    "dynamodb:getitem",
    "dynamodb:batchgetitem",
    "dynamodb:query",
    "dynamodb:scan",
    "dynamodb:partiqlselect",
    "dynamodb:exporttabletopointintime",
    "dynamodb:getrecords",
}


def _table_suffixes(template: dict) -> dict[str, str]:
    """Protected table -> the name it gets after the stack prefix."""
    suffixes = {}
    for table in TABLE_READERS:
        name = resources(template, "AWS::DynamoDB::Table").get(table, {}).get("Properties", {}).get("TableName")
        text = name.get("Fn::Sub", "") if isinstance(name, dict) else str(name or "")
        if text:
            suffixes[table] = text.split("}")[-1].lstrip("-") or text
    return suffixes


def _arn_names(text: str, suffixes: dict[str, str]) -> set[str]:
    """What an ARN string reaches: the logical ids it names (a wildcard after
    one stays under it, such as an index of that table), a protected table
    named literally, or everything ("*") for a wildcard naming nothing."""
    refs = set(re.findall(r"\$\{([A-Za-z0-9]+)[.}]", text))
    found = set(refs)
    found |= {table for table, suffix in suffixes.items() if suffix and suffix in text}
    if not found and ("*" in text or "?" in text):
        found.add("*")
    return found


def _names(value, suffixes: dict[str, str] | None = None) -> set[str]:
    """Logical ids a Resource value refers to, and "*" for a wildcard."""
    suffixes = suffixes or {}
    found: set[str] = set()
    if isinstance(value, str):
        found |= _arn_names(value, suffixes)
    elif isinstance(value, list):
        for item in value:
            found |= _names(item, suffixes)
    elif isinstance(value, dict):
        name = logical_id(value)
        if name:
            found.add(name)
        if "Fn::Sub" in value:
            text = value["Fn::Sub"][0] if isinstance(value["Fn::Sub"], list) else value["Fn::Sub"]
            found |= _arn_names(str(text), suffixes)
        for key, item in value.items():
            if key not in ("Ref", "Fn::GetAtt", "Fn::Sub"):
                found |= _names(item, suffixes)
    return found


def _statements(template: dict):
    """(role or policy name, attached roles, statement) for every IAM statement."""
    for name, role in resources(template, "AWS::IAM::Role").items():
        for policy in _policies(role):
            for st in policy.get("PolicyDocument", {}).get("Statement", []):
                yield name, {name}, st
    for kind in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::RolePolicy"):
        for name, policy in resources(template, kind).items():
            props = policy.get("Properties", {})
            attached = ({logical_id(r) for r in props.get("Roles", [])} | {logical_id(props.get("RoleName"))}) - {None}
            for st in props.get("PolicyDocument", {}).get("Statement", []):
                yield name, attached, st


def check_table_readers(template: dict) -> list[str]:
    problems = []
    suffixes = _table_suffixes(template)
    for name, attached, st in _statements(template):
        if st.get("Effect") != "Allow":
            continue
        actions = [a.lower() for a in _actions(st) if isinstance(a, str)]
        # A pattern such as dynamodb:Get* reads as much as the action it covers.
        reads = {r for r in READ_ACTIONS if covers(actions, r)}
        if not reads:
            continue
        targets = _names(st.get("Resource"), suffixes)
        for table, readers in TABLE_READERS.items():
            if table not in targets and "*" not in targets:
                continue
            if "dynamodb:exporttabletopointintime" in reads:
                problems.append(f"{name}: may export {table}, whose items are capabilities")
            if not attached <= readers:
                problems.append(f"{name}: may read {table}; only {', '.join(sorted(readers))} may")
    return problems


REQUIRED_ACTIONS = pathlib.Path(__file__).resolve().parent.parent / "infra" / "task-role-actions.yaml"


def _resource_keys(value) -> list[str]:
    """A statement's resources written like the keys of task-role-actions.yaml:
    GetAtt X.Arn is "X", Sub '${X.Arn}/index/a' is "X/index/a"."""
    items = value if isinstance(value, list) else [value]
    keys = []
    for item in items:
        if isinstance(item, str):
            keys.append(item)
        elif isinstance(item, dict) and "Fn::Sub" in item:
            text = item["Fn::Sub"][0] if isinstance(item["Fn::Sub"], list) else item["Fn::Sub"]
            keys.append(re.sub(r"\$\{([A-Za-z0-9]+)\.Arn\}", r"\1", str(text)))
        elif isinstance(item, dict):
            name = logical_id(item)
            if name:
                keys.append(name)
    return keys


def check_required_actions(template: dict, required: dict | None = None) -> list[str]:
    """Every action a service's code calls is granted on its resource.

    A wildcard grants what it matches, by shell pattern on both the action
    and the resource key.
    """
    if required is None:
        import yaml  # cfn-lint's dependency, in the infra tools image

        required = yaml.safe_load(REQUIRED_ACTIONS.read_text())
    roles = resources(template, "AWS::IAM::Role")
    problems = []
    for role, needs in sorted(required.items()):
        if role not in roles:
            problems.append(f"{role}: in task-role-actions.yaml but not in the template")
            continue
        grants = []
        for policy in _policies(roles[role]):
            for st in policy.get("PolicyDocument", {}).get("Statement", []):
                if st.get("Effect") == "Allow":
                    grants.append(([a.lower() for a in _actions(st) if isinstance(a, str)], _resource_keys(st.get("Resource"))))
        for resource, actions in needs.items():
            for action in actions:
                if not any(any(fnmatch.fnmatchcase(action.lower(), a) for a in acts) and
                           any(fnmatch.fnmatchcase(resource, r) for r in keys) for acts, keys in grants):
                    problems.append(f"{role}: lacks {action} on {resource}, which its code calls")
    return problems


# Actions an Allow may grant on Resource "*": those whose API has no resource
# to name. Everything else names its resources.
STAR_ACTIONS = {
    "ecr:getauthorizationtoken",
    "sms-voice:sendtextmessage",
    "sns:publish",  # with a Deny on every topic (phone numbers only), checked below
    "servicediscovery:discoverinstances",  # held to one service by a condition
}


def check_iam_statements(template: dict) -> list[str]:
    """No NotAction or NotResource in an Allow; Resource "*" only for the
    actions that cannot name one; SNS publishing to numbers, not topics."""
    problems = []
    denies: dict[str, list[dict]] = {}
    for name, _, st in _statements(template):
        if st.get("Effect") == "Deny":
            denies.setdefault(name, []).append(st)
    for name, _, st in _statements(template):
        if st.get("Effect") != "Allow":
            continue
        for key in ("NotAction", "NotResource", "NotPrincipal"):
            if key in st:
                problems.append(f"{name}: an Allow with {key} grants everything it does not name")
        resource = st.get("Resource")
        if resource == "*" or (isinstance(resource, list) and "*" in resource):
            for action in _actions(st):
                if not isinstance(action, str) or action.lower() not in STAR_ACTIONS:
                    problems.append(f"{name}: {action} on Resource '*'; name the resource")
            if covers(_actions(st), "sns:publish") and not any(
                    covers(_actions(d), "sns:publish") and ":sns:*" in str(d.get("Resource")) for d in denies.get(name, [])):
                problems.append(f"{name}: sns:Publish on '*' without a Deny on topics reaches every topic")
    return problems


# Scan reads a whole table; only these may (role, resource as in
# task-role-actions.yaml).
SCAN_ALLOWED = {
    ("FtServerTaskRole", "FilesTable"),
    ("HssTaskRole", "SubscribersTable/index/profile-index"),
}


def check_scans(template: dict) -> list[str]:
    problems = []
    for name, _, st in _statements(template):
        if st.get("Effect") == "Allow" and covers(_actions(st), "dynamodb:scan"):
            for key in _resource_keys(st.get("Resource")):
                if (name, key) not in SCAN_ALLOWED:
                    problems.append(f"{name}: may Scan {key}; only {', '.join(f'{r} on {k}' for r, k in sorted(SCAN_ALLOWED))} may")
    return problems


# Who may use each key (Encrypt, Decrypt, GenerateDataKey, ReEncrypt,
# CreateGrant): roles by logical id, services as "service:<principal>". The
# account root may administer a key but never use it.
KEY_USERS = {
    "HssKey": {"HssTaskRole"},
    "AlarmKey": {"service:cloudwatch.amazonaws.com", "service:events.amazonaws.com", "service:budgets.amazonaws.com"},
    "ScscfStateKey": {"ScscfTaskRole", "deploy"},
}
KEY_USE = ("kms:encrypt", "kms:decrypt", "kms:reencryptfrom", "kms:reencryptto", "kms:generatedatakey",
           "kms:generatedatakeywithoutplaintext", "kms:creategrant")


def _key_principals(statement: dict) -> set[str]:
    principal = statement.get("Principal", {})
    if principal == "*":
        return {"*"}
    found = set()
    services = principal.get("Service", []) if isinstance(principal, dict) else []
    found |= {f"service:{s}" for s in ([services] if isinstance(services, str) else services)}
    for value in (principal.get("AWS", []) if isinstance(principal, dict) else []) if not isinstance(
            principal.get("AWS") if isinstance(principal, dict) else None, (str, dict)) else [principal["AWS"]]:
        if isinstance(value, dict) and "Fn::Sub" in value and ":root" in str(value["Fn::Sub"]):
            # The root, narrowed to the deploying principal by a condition,
            # is the deployer; otherwise the whole account.
            arn = statement.get("Condition", {}).get("StringEquals", {}).get("aws:PrincipalArn")
            found.add("deploy" if logical_id(arn) == "DeployPrincipalArn" else "root")
        else:
            found.add(logical_id(value) or str(value))
    return found


def check_key_policies(template: dict) -> list[str]:
    problems = []
    for name, key in resources(template, "AWS::KMS::Key").items():
        users = KEY_USERS.get(name)
        if users is None:
            problems.append(f"{name}: not in KEY_USERS; say who may use it")
            continue
        for st in key.get("Properties", {}).get("KeyPolicy", {}).get("Statement", []):
            if st.get("Effect") != "Allow" or not covers(_actions(st), KEY_USE) and "NotAction" not in st:
                continue
            for who in sorted(_key_principals(st) - users):
                problems.append(f"{name}: {who} may use the key; only {', '.join(sorted(users))} may")
    return problems


def check_topics(template: dict) -> list[str]:
    """Topics are encrypted, and a topic policy, which replaces the default,
    lets in every service that publishes to the topic."""
    problems = []
    publishers: dict[str, set[str]] = {}
    for alarm in resources(template, "AWS::CloudWatch::Alarm").values():
        for target in alarm.get("Properties", {}).get("AlarmActions", []):
            for topic in _names(target):
                publishers.setdefault(topic, set()).add("cloudwatch.amazonaws.com")
    for rule in resources(template, "AWS::Events::Rule").values():
        for target in rule.get("Properties", {}).get("Targets", []):
            for topic in _names(target.get("Arn")):
                publishers.setdefault(topic, set()).add("events.amazonaws.com")
    for budget in resources(template, "AWS::Budgets::Budget").values():
        for notification in budget.get("Properties", {}).get("NotificationsWithSubscribers", []):
            for sub in notification.get("Subscribers", []):
                for topic in _names(sub.get("Address")):
                    publishers.setdefault(topic, set()).add("budgets.amazonaws.com")
    allowed: dict[str, set[str]] = {}
    for policy in resources(template, "AWS::SNS::TopicPolicy").values():
        props = policy.get("Properties", {})
        for st in props.get("PolicyDocument", {}).get("Statement", []):
            services = st.get("Principal", {}).get("Service", []) if isinstance(st.get("Principal"), dict) else []
            for topic in props.get("Topics", []):
                allowed.setdefault(logical_id(topic), set()).update([services] if isinstance(services, str) else services)
    for name, topic in resources(template, "AWS::SNS::Topic").items():
        if not topic.get("Properties", {}).get("KmsMasterKeyId"):
            problems.append(f"{name}: not encrypted (KmsMasterKeyId)")
        for service in sorted(publishers.get(name, set()) - allowed.get(name, set())):
            problems.append(f"{name}: {service} publishes to it but its topic policy does not allow it")
    return problems


def check_task_images_and_values(template: dict) -> list[str]:
    """Images by digest, so a task starts from the bytes deploy.sh checked;
    no secret resolved into a plain environment value or an output."""
    problems = []
    for name, td in resources(template, "AWS::ECS::TaskDefinition").items():
        for c in td.get("Properties", {}).get("ContainerDefinitions", []):
            image = c.get("Image")
            text = image.get("Fn::Sub", "") if isinstance(image, dict) else image
            text = text[0] if isinstance(text, list) else text
            if "@" not in str(text):
                problems.append(f"{name}/{c.get('Name', '?')}: image by tag; refer to it by digest (@sha256:...)")
            for env in c.get("Environment", []):
                if "resolve:secretsmanager" in str(env.get("Value")) or "resolve:ssm-secure" in str(env.get("Value")):
                    problems.append(f"{name}/{c.get('Name', '?')}: {env.get('Name')} resolves a secret into plain text")
    for name, output in template.get("Outputs", {}).items():
        if "resolve:secretsmanager" in str(output.get("Value")):
            problems.append(f"output {name}: resolves a secret")
    return problems


# ECS services and their own groups (ADR 0007 §2): private subnets, no public
# address.
SERVICE_GROUPS = {
    "HssService": "HssSecurityGroup",
    "FtServerService": "FtServerSecurityGroup",
    "RelayService": "MsrpRelaySecurityGroup",
    "AcsService": "AcsSecurityGroup",
}
PRIVATE_SUBNETS = {"PrivateSubnetA", "PrivateSubnetB"}


def check_services(template: dict) -> list[str]:
    problems = []
    for name, svc in resources(template, "AWS::ECS::Service").items():
        net = svc.get("Properties", {}).get("NetworkConfiguration", {}).get("AwsvpcConfiguration", {})
        groups = {logical_id(g) for g in net.get("SecurityGroups", [])}
        if name not in SERVICE_GROUPS:
            problems.append(f"{name}: not in SERVICE_GROUPS; give it its own security group")
        elif groups != {SERVICE_GROUPS[name]}:
            problems.append(f"{name}: runs in {sorted(groups)}, not only its own {SERVICE_GROUPS[name]}")
        if str(net.get("AssignPublicIp", "DISABLED")).upper() != "DISABLED":
            problems.append(f"{name}: tasks get a public address")
        subnets = {logical_id(s) for s in net.get("Subnets", [])}
        if not subnets or not subnets <= PRIVATE_SUBNETS:
            problems.append(f"{name}: tasks outside the private subnets")
    return problems


CHECKS = (
    check_security_groups,
    check_target_groups,
    check_plain_listeners,
    check_load_balancers,
    check_waf,
    check_tasks,
    check_tables,
    check_buckets,
    check_secret_access,
    check_iam_statements,
    check_scans,
    check_key_policies,
    check_topics,
    check_task_images_and_values,
    check_services,
    check_table_readers,
    check_required_actions,
)


def problems(template: dict) -> list[str]:
    found = []
    for check in CHECKS:
        found += check(template)
    return found


def main(paths: list[str]) -> int:
    status = 0
    for path in paths:
        for problem in problems(load(path)):
            print(f"{path}: {problem}")
            status = 1
    if status == 0:
        print(f"policy checks passed: {', '.join(paths)}")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
