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
  (ADR 0007 §9); hss's health check outlasts HSS_START_TIMEOUT;
* every DynamoDB table has point-in-time recovery (ADR 0003);
* no task role can read a secret: secrets reach tasks through the execution
  role only (ADR 0007 §4);
* tables holding capabilities or message content are read only by their own
  service's task role, and nothing may export them: msrp-bindings holds
  rcs-as session ids (threat model T3, #54), messages holds queued messages,
  the S-CSCF tables hold IMPIs and device addresses, under their own key; a
  wildcard ARN, or one naming the table, counts;
* every task role is granted each action its service's code calls
  (infra/task-role-actions.yaml);
* alarms follow the EMF rules of docs/architecture.md §8: periods of 60 s or
  more, N >= 2, explicit treatMissingData, no sampled timing statistics;
* with --runbook, every alarm links the runbook section named after it, and
  that section exists, so whoever is paged lands on what to do.

Runs in the infra tools image (deploy/infra-tools.Dockerfile), which provides
cfn-lint's CloudFormation YAML decoder. Usage:
check_infra.py [--runbook docs/runbook.md] TEMPLATE...
Exit status 1 lists every problem.
"""

from __future__ import annotations

import fnmatch
import importlib.util
import pathlib
import re
import sys
from dataclasses import dataclass

# (destination group, port) -> source groups. ADR 0007 §2; ports as listed at
# the security groups in infra/platform.yaml.
EXPECTED_INGRESS: dict[tuple[str, int], set[str]] = {
    ("PcscfSecurityGroup", 5060): {"NlbSecurityGroup"},
    ("PcscfSecurityGroup", 5070): {"ScscfSecurityGroup"},
    ("IcscfSecurityGroup", 5060): {"PcscfSecurityGroup", "RcsAsSecurityGroup", "ScscfSecurityGroup"},
    ("ScscfSecurityGroup", 5060): {"PcscfSecurityGroup", "RcsAsSecurityGroup", "IcscfSecurityGroup"},
    ("RcsAsSecurityGroup", 5060): {"ScscfSecurityGroup", "IcscfSecurityGroup"},
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
    return problems


def check_tasks(template: dict) -> list[str]:
    problems = []
    for name, td in resources(template, "AWS::ECS::TaskDefinition").items():
        for c in td.get("Properties", {}).get("ContainerDefinitions", []):
            where = f"{name}/{c.get('Name', '?')}"
            if c.get("ReadonlyRootFilesystem") is not True:
                problems.append(f"{where}: root file system is not read-only")
            if c.get("Privileged") is True:
                problems.append(f"{where}: privileged")
            drop = c.get("LinuxParameters", {}).get("Capabilities", {}).get("Drop", [])
            if "ALL" not in drop:
                problems.append(f"{where}: does not drop all Linux capabilities")
            if c.get("LinuxParameters", {}).get("Capabilities", {}).get("Add"):
                problems.append(f"{where}: adds Linux capabilities")
    for name, svc in resources(template, "AWS::ECS::Service").items():
        if svc.get("Properties", {}).get("EnableExecuteCommand") not in (None, False, "false"):
            problems.append(f"{name}: ECS Exec is enabled")
    return problems


# ECS allows a container health check StartPeriod of 300 s at most.
MAX_START_TIMEOUT = 240


def _seconds(value) -> float | None:
    """A Go duration of whole units (60s, 4m, 1m30s), or None."""
    if not isinstance(value, str):
        return None
    parts = re.findall(r"(\d+)(h|m|s)", value)
    if not parts or "".join(n + u for n, u in parts) != value:
        return None
    return sum(int(n) * {"h": 3600, "m": 60, "s": 1}[u] for n, u in parts)


def check_start_period(template: dict) -> list[str]:
    """hss's container health check outlasts its start timeout.

    hss exits once HSS_START_TIMEOUT passes without its store and keyring,
    which the deployment circuit breaker sees. A health check that gave up
    first would stop the task for a different reason, hiding that one.
    """
    problems = []
    for name, td in resources(template, "AWS::ECS::TaskDefinition").items():
        for c in td.get("Properties", {}).get("ContainerDefinitions", []):
            env = {e.get("Name"): e.get("Value") for e in c.get("Environment", [])}
            if "HSS_START_TIMEOUT" not in env:
                continue
            where = f"{name}/{c.get('Name', '?')}"
            timeout = _seconds(env["HSS_START_TIMEOUT"])
            check = c.get("HealthCheck", {})
            if timeout is None:
                problems.append(f"{where}: HSS_START_TIMEOUT is not a duration in h, m and s")
                continue
            if timeout > MAX_START_TIMEOUT:
                problems.append(f"{where}: HSS_START_TIMEOUT is over {MAX_START_TIMEOUT} s")
            grace = check.get("StartPeriod", 0) + check.get("Interval", 30) * check.get("Retries", 3)
            if grace <= timeout:
                problems.append(f"{where}: StartPeriod + Interval x Retries ({grace} s) must exceed HSS_START_TIMEOUT ({timeout:g} s)")
    return problems


def check_table_keys(template: dict) -> list[str]:
    problems = []
    tables = resources(template, "AWS::DynamoDB::Table")
    for name in sorted(CMK_TABLES):
        sse = tables.get(name, {}).get("Properties", {}).get("SSESpecification", {})
        if sse.get("SSEType") != "KMS" or logical_id(sse.get("KMSMasterKeyId")) not in resources(template, "AWS::KMS::Key"):
            problems.append(f"{name}: not encrypted with a customer-managed key of the stack")
    return problems


def _namespace(metric: dict) -> str:
    ns = metric.get("Namespace", "")
    return ns.get("Fn::Sub", "") if isinstance(ns, dict) else ns


def check_alarm_rules(template: dict) -> list[str]:
    """The alarm rules of docs/architecture.md §8 for EMF metrics.

    A minute's EMF values arrive up to a minute late and a task's flushes are
    not aligned, so every alarm uses periods of 60 s or more and N >= 2
    evaluation periods, and states treatMissingData. On the services' own
    metrics, counts (Sum) treat missing as not breaching, except an alarm
    that fires on too few (missing then is the breach); gauges and latency
    Maximums treat missing as missing or ignore; and no alarm uses a
    statistic that describes a timing's sampled values (SampleCount, Average).
    """
    problems = []
    for name, alarm in resources(template, "AWS::CloudWatch::Alarm").items():
        props = alarm.get("Properties", {})
        stats = [m["MetricStat"] for m in props.get("Metrics", []) if "MetricStat" in m]
        if "MetricName" in props:
            stats.append({"Metric": props, "Period": props.get("Period"), "Stat": props.get("Statistic")})
        if not isinstance(props.get("EvaluationPeriods"), int) or props["EvaluationPeriods"] < 2:
            problems.append(f"{name}: EvaluationPeriods must be 2 or more")
        missing = props.get("TreatMissingData")
        if missing is None:
            problems.append(f"{name}: TreatMissingData is not set")
        for stat in stats:
            if not isinstance(stat.get("Period"), int) or stat["Period"] < 60:
                problems.append(f"{name}: a period is under 60 s")
            if not _namespace(stat.get("Metric", {})).startswith("RCS/"):
                continue
            kind = stat.get("Stat")
            if kind == "Sum":
                fewer = str(props.get("ComparisonOperator", "")).startswith("LessThan")
                if missing != ("breaching" if fewer else "notBreaching"):
                    problems.append(f"{name}: a count treats missing data as {missing}")
            elif kind == "Maximum":
                if missing not in ("missing", "ignore"):
                    problems.append(f"{name}: a gauge or latency treats missing data as {missing}")
            else:
                problems.append(f"{name}: statistic {kind} on a service metric (use Sum or Maximum)")
    return problems


def check_tables(template: dict) -> list[str]:
    problems = []
    for name, table in resources(template, "AWS::DynamoDB::Table").items():
        pitr = table.get("Properties", {}).get("PointInTimeRecoverySpecification", {})
        if pitr.get("PointInTimeRecoveryEnabled") is not True:
            problems.append(f"{name}: point-in-time recovery is off")
    return problems


def _actions(statement: dict) -> list[str]:
    actions = statement.get("Action", [])
    return [actions] if isinstance(actions, str) else list(actions)


def _reads_secrets(document: dict) -> bool:
    for statement in document.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        for action in _actions(statement):
            if isinstance(action, str) and (action == "*" or action.lower().startswith("secretsmanager:")):
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
    for kind in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
        for name, policy in resources(template, kind).items():
            props = policy.get("Properties", {})
            attached = {logical_id(r) for r in props.get("Roles", [])}
            if attached & roles_of_tasks and _reads_secrets(props.get("PolicyDocument", {})):
                problems.append(f"{name}: lets a task role read secrets (only execution roles may)")
    return problems


# Tables whose items are capabilities or message content, and the only roles
# that may read them.
TABLE_READERS: dict[str, set[str]] = {
    "MsrpBindingsTable": {"MsrpRelayTaskRole"},
    "MessagesTable": {"RcsAsTaskRole"},
    "RegistrationsTable": {"ScscfTaskRole"},
    "AuthChallengesTable": {"ScscfTaskRole"},
    "RegSubscriptionsTable": {"ScscfTaskRole"},
}

# Tables encrypted with a customer-managed key of the stack: their items
# hold IMPIs, contact addresses and instance ids (docs/scscf-state.md).
CMK_TABLES = {"RegistrationsTable", "AuthChallengesTable", "RegSubscriptionsTable"}

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
    for kind in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
        for name, policy in resources(template, kind).items():
            props = policy.get("Properties", {})
            attached = {logical_id(r) for r in props.get("Roles", [])} - {None}
            for st in props.get("PolicyDocument", {}).get("Statement", []):
                yield name, attached, st


def check_table_readers(template: dict) -> list[str]:
    problems = []
    suffixes = _table_suffixes(template)
    for name, attached, st in _statements(template):
        if st.get("Effect") != "Allow":
            continue
        actions = {a.lower() for a in _actions(st) if isinstance(a, str)}
        reads = {a for a in actions if a in READ_ACTIONS or a in ("*", "dynamodb:*")}
        if not reads:
            continue
        targets = _names(st.get("Resource"), suffixes)
        for table, readers in TABLE_READERS.items():
            if table not in targets and "*" not in targets:
                continue
            if "dynamodb:exporttabletopointintime" in reads or "*" in reads or "dynamodb:*" in reads:
                problems.append(f"{name}: may export {table}, whose items are capabilities")
            if not attached <= readers:
                problems.append(f"{name}: may read {table}; only {', '.join(sorted(readers))} may")
    return problems


RUNBOOK_LINK = re.compile(r"docs/runbook\.md#([\w-]+)")


def check_runbook(template: dict, anchors: set[str]) -> list[str]:
    """Every alarm links exactly its own runbook section, which exists.

    The section is named after the alarm's logical id (also its AlarmName
    after the stack prefix), so the anchor is the id in lower case.
    """
    problems = []
    for name, alarm in resources(template, "AWS::CloudWatch::Alarm").items():
        anchor = name.lower()
        description = alarm.get("Properties", {}).get("AlarmDescription")
        links = RUNBOOK_LINK.findall(description) if isinstance(description, str) else []
        if links != [anchor]:
            problems.append(f"{name}: the description must link docs/runbook.md#{anchor} and nothing else")
        elif anchor not in anchors:
            problems.append(f"{name}: docs/runbook.md has no section {name}")
    return problems


def runbook_anchors(path: str) -> set[str]:
    """Heading anchors of a Markdown file, as `make docs` computes them."""
    source = pathlib.Path(__file__).resolve().parent / "check-links.py"
    spec = importlib.util.spec_from_file_location("check_links", source)
    links = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(links)
    return links.anchors(pathlib.Path(path).read_text())


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


CHECKS = (
    check_security_groups,
    check_target_groups,
    check_plain_listeners,
    check_waf,
    check_tasks,
    check_start_period,
    check_tables,
    check_table_keys,
    check_alarm_rules,
    check_secret_access,
    check_table_readers,
    check_required_actions,
)


def problems(template: dict) -> list[str]:
    found = []
    for check in CHECKS:
        found += check(template)
    return found


def main(args: list[str]) -> int:
    anchors = None
    if args[:1] == ["--runbook"]:
        anchors, args = runbook_anchors(args[1]), args[2:]
    paths, status = args, 0
    for path in paths:
        template = load(path)
        found = problems(template)
        if anchors is not None:
            found += check_runbook(template, anchors)
        for problem in found:
            print(f"{path}: {problem}")
            status = 1
    if status == 0:
        print(f"policy checks passed: {', '.join(paths)}")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
