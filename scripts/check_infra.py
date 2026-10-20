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
  role only (ADR 0007 §4).

Runs in the infra tools image (deploy/infra-tools.Dockerfile), which provides
cfn-lint's CloudFormation YAML decoder. Usage: check_infra.py TEMPLATE...
Exit status 1 lists every problem.
"""

from __future__ import annotations

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
        if not isinstance(protocol, str):
            problems.append(f"{name}: the protocol must be literal for this check to see it")
            continue
        if protocol in PLAIN_PROTOCOLS and not dev_only(template, listener.get("Condition")):
            problems.append(f"{name}: a plain {protocol} listener outside dev (ADR 0003)")
    # With a certificate, the ALB's HTTP listener only redirects, and no rule
    # forwards on it; it forwards only without one (dev, see the Rules).
    for name, listener in resources(template, "AWS::ElasticLoadBalancingV2::Listener").items():
        props = listener.get("Properties", {})
        if props.get("Protocol") != "HTTP":
            continue
        for action in props.get("DefaultActions", []):
            if not (isinstance(action, dict) and "Fn::If" in action):
                problems.append(f"{name}: the HTTP listener acts the same with a certificate; it must redirect then")
                continue
            condition, with_certificate, _ = action["Fn::If"]
            if condition != "HasAlbCertificate" or with_certificate.get("Type") != "redirect":
                problems.append(f"{name}: with a certificate the HTTP listener must redirect to HTTPS")
        for rule_name, rule in resources(template, "AWS::ElasticLoadBalancingV2::ListenerRule").items():
            arn = rule.get("Properties", {}).get("ListenerArn")
            if logical_id(arn) == name:
                problems.append(f"{rule_name}: forwards on the HTTP listener even with a certificate")
            elif isinstance(arn, dict) and "Fn::If" in arn:
                condition, with_certificate, _ = arn["Fn::If"]
                if condition != "HasAlbCertificate" or logical_id(with_certificate) == name:
                    problems.append(f"{rule_name}: forwards on the HTTP listener even with a certificate")
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


def check_secret_access(template: dict) -> list[str]:
    task_roles = {
        logical_id(td.get("Properties", {}).get("TaskRoleArn"))
        for td in resources(template, "AWS::ECS::TaskDefinition").values()
    } - {None}
    problems = []
    for name, td in resources(template, "AWS::ECS::TaskDefinition").items():
        props = td.get("Properties", {})
        task = logical_id(props.get("TaskRoleArn"))
        if task is not None and task == logical_id(props.get("ExecutionRoleArn")):
            problems.append(f"{name}: the task role is also the execution role, so the task can read its secrets")
    roles = resources(template, "AWS::IAM::Role")
    for name in sorted(task_roles):
        role = roles.get(name, {}).get("Properties", {})
        for policy in role.get("Policies", []):
            if _reads_secrets(policy.get("PolicyDocument", {})):
                problems.append(f"{name}: a task role may read secrets (only execution roles may)")
        if role.get("ManagedPolicyArns"):
            problems.append(f"{name}: a task role has managed policies, which this check cannot see into")
    for kind in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
        for name, policy in resources(template, kind).items():
            props = policy.get("Properties", {})
            attached = {logical_id(r) for r in props.get("Roles", [])}
            if attached & task_roles and _reads_secrets(props.get("PolicyDocument", {})):
                problems.append(f"{name}: lets a task role read secrets (only execution roles may)")
    return problems


CHECKS = (check_security_groups, check_target_groups, check_plain_listeners, check_load_balancers, check_waf, check_tasks, check_tables, check_secret_access)


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
