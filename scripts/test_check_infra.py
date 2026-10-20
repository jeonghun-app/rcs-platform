"""Tests of scripts/check_infra.py: the real template passes, and each policy
fails on a template changed to break it. Run with
python3 -m unittest discover -s scripts -p 'test_check_infra.py' in the infra
tools image (make infra-lint)."""

from __future__ import annotations

import copy
import pathlib
import re
import unittest

import check_infra

TEMPLATE = pathlib.Path(__file__).resolve().parent.parent / "infra" / "platform.yaml"


def ingress(group: str, port: int, **peer) -> dict:
    props = {"GroupId": {"Ref": group}, "IpProtocol": "tcp", "FromPort": port, "ToPort": port}
    props.update(peer)
    return {"Type": "AWS::EC2::SecurityGroupIngress", "Properties": props}


def task_definition(**container) -> dict:
    c = {
        "Name": "svc",
        "Image": "registry.example/svc@sha256:" + "ab" * 32,
        "ReadonlyRootFilesystem": True,
        "LinuxParameters": {"Capabilities": {"Drop": ["ALL"]}},
    }
    c.update(container)
    return {
        "Type": "AWS::ECS::TaskDefinition",
        "Properties": {
            "ContainerDefinitions": [c],
            "TaskRoleArn": {"Fn::GetAtt": ["SvcTaskRole", "Arn"]},
            "ExecutionRoleArn": {"Fn::GetAtt": ["SvcExecutionRole", "Arn"]},
        },
    }


def not_listing(problems: list[str]) -> list[str]:
    """Problems other than a fixture's task role missing from
    task-role-actions.yaml, which a synthetic role always is."""
    return [p for p in problems if "task-role-actions.yaml" not in p]


def role(*actions: str) -> dict:
    return {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "Policies": [
                {"PolicyName": "p", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": list(actions),
                                                                      "Resource": "arn:aws:dynamodb:ap-northeast-2:123456789012:table/other"}]}}
            ]
        },
    }


class TemplateCase(unittest.TestCase):
    """Loads infra/platform.yaml once and changes copies of it."""

    @classmethod
    def setUpClass(cls):
        cls.template = check_infra.load(str(TEMPLATE))

    def changed(self, **resources) -> dict:
        t = copy.deepcopy(self.template)
        for name, resource in resources.items():
            if resource is None:
                del t["Resources"][name]
            else:
                t["Resources"][name] = resource
        return t

    def assertProblem(self, template: dict, fragment: str):
        found = check_infra.problems(template)
        self.assertTrue(any(fragment in p for p in found), f"no problem with {fragment!r} in {found}")


class PlatformTemplate(TemplateCase):
    """Policies on the network, security groups and load balancers."""

    def test_the_platform_template_meets_every_policy(self):
        self.assertEqual(check_infra.problems(self.template), [])

    def test_every_matrix_entry_is_in_the_template(self):
        ingress_rules, _ = check_infra.collect(self.template)
        got = {(r.group, r.from_port, r.peer_group) for r in ingress_rules if r.peer_group}
        for (group, port), sources in check_infra.EXPECTED_INGRESS.items():
            for source in sources:
                self.assertIn((group, port, source), got)

    def test_an_address_range_on_a_private_group_is_refused(self):
        t = self.changed(Leak=ingress("HssSecurityGroup", 8081, CidrIp="10.0.0.0/8"))
        self.assertProblem(t, "HssSecurityGroup ingress tcp 8081-8081: admits an address range")

    def test_a_source_outside_the_matrix_is_refused(self):
        t = self.changed(Extra=ingress("RcsAsSecurityGroup", 2855, SourceSecurityGroupId={"Ref": "PcscfSecurityGroup"}))
        self.assertProblem(t, "RcsAsSecurityGroup port 2855: PcscfSecurityGroup is not in the ADR 0007 matrix")

    def test_a_port_outside_the_matrix_is_refused(self):
        t = self.changed(Extra=ingress("HssSecurityGroup", 22, SourceSecurityGroupId={"Ref": "OperatorSecurityGroup"}))
        self.assertProblem(t, "HssSecurityGroup port 22: OperatorSecurityGroup is not in the ADR 0007 matrix")

    def test_a_missing_matrix_entry_is_reported(self):
        t = self.changed(RelayToRcsAsMsrp=None)
        self.assertProblem(t, "RcsAsSecurityGroup port 2855: MsrpRelaySecurityGroup is missing")

    def test_ingress_without_its_egress_is_reported(self):
        t = self.changed(RelayToRcsAsMsrpOut=None)
        self.assertProblem(t, "MsrpRelaySecurityGroup egress to RcsAsSecurityGroup port 2855 is missing")

    def test_port_ranges_and_all_protocols_are_refused(self):
        t = self.changed(Range=ingress("HssSecurityGroup", 8081, ToPort=8090, SourceSecurityGroupId={"Ref": "AcsSecurityGroup"}))
        self.assertProblem(t, "rules are single TCP ports")
        t = copy.deepcopy(self.template)
        t["Resources"]["HssSecurityGroup"]["Properties"]["SecurityGroupEgress"].append(
            {"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}
        )
        self.assertProblem(t, "only HTTPS for the AWS APIs may leave to an address range")

    def test_a_group_without_inline_egress_keeps_the_default_and_is_refused(self):
        t = copy.deepcopy(self.template)
        del t["Resources"]["AcsSecurityGroup"]["Properties"]["SecurityGroupEgress"]
        self.assertProblem(t, "AcsSecurityGroup: no inline egress rule")

    def test_a_public_port_outside_the_listeners_is_refused(self):
        t = self.changed(Ssh=ingress("NlbSecurityGroup", 22, CidrIp="0.0.0.0/0"))
        self.assertProblem(t, "NlbSecurityGroup ingress tcp 22-22: admits an address range")

    def test_an_nlb_target_group_without_proxy_protocol_is_refused(self):
        t = copy.deepcopy(self.template)
        attrs = t["Resources"]["RelayMsrpTargetGroup"]["Properties"]["TargetGroupAttributes"]
        attrs[:] = [a for a in attrs if a["Key"] != "proxy_protocol_v2.enabled"]
        self.assertProblem(t, "RelayMsrpTargetGroup: NLB target group without Proxy Protocol v2")

    def test_an_nlb_target_group_preserving_client_addresses_is_refused(self):
        t = copy.deepcopy(self.template)
        attrs = t["Resources"]["RelayMsrpTargetGroup"]["Properties"]["TargetGroupAttributes"]
        attrs[:] = [a for a in attrs if a["Key"] != "preserve_client_ip.enabled"]
        self.assertProblem(t, "RelayMsrpTargetGroup: NLB target group must not preserve client addresses")

    def test_an_nlb_target_group_resetting_connections_is_refused(self):
        t = copy.deepcopy(self.template)
        for a in t["Resources"]["RelayMsrpTargetGroup"]["Properties"]["TargetGroupAttributes"]:
            if a["Key"] == "deregistration_delay.connection_termination.enabled":
                a["Value"] = "true"
        self.assertProblem(t, "RelayMsrpTargetGroup: NLB target group must keep connections at deregistration")

    def test_a_plain_listener_outside_dev_is_refused(self):
        t = copy.deepcopy(self.template)
        del t["Resources"]["MsrpTcpListener"]["Condition"]
        self.assertProblem(t, "MsrpTcpListener: a plain TCP listener outside dev (ADR 0003)")

    def test_a_plain_sip_listener_with_pcscf_alone_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["SipTcpListener"]["Condition"] = "WithPcscf"
        self.assertProblem(t, "SipTcpListener: a plain TCP listener outside dev")

    def test_a_plain_port_open_outside_dev_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["NlbSecurityGroup"]["Properties"]["SecurityGroupIngress"].append(
            {"IpProtocol": "tcp", "FromPort": 2855, "ToPort": 2855, "CidrIp": "0.0.0.0/0"})
        self.assertProblem(t, "NlbSecurityGroup: plain port 2855 open outside dev (ADR 0003)")

    def test_the_tls_listeners_are_not_dev_only(self):
        listeners = check_infra.resources(self.template, "AWS::ElasticLoadBalancingV2::Listener")
        self.assertFalse(check_infra.dev_only(self.template, listeners["MsrpTlsListener"].get("Condition")))

    def test_a_load_balancer_group_sending_to_the_internet_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["AlbSecurityGroup"]["Properties"]["SecurityGroupEgress"].append(
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "0.0.0.0/0"})
        self.assertProblem(t, "AlbSecurityGroup egress tcp 443-443: an internet-facing group sends to an address range")

    def test_a_group_admitted_into_a_load_balancer_group_is_refused(self):
        t = self.changed(Back=ingress("NlbSecurityGroup", 5061, SourceSecurityGroupId={"Ref": "HssSecurityGroup"}))
        self.assertProblem(t, "NlbSecurityGroup ingress tcp 5061-5061: an internet-facing group admits only clients")

    def test_egress_outside_the_matrix_is_refused(self):
        t = self.changed(Stray={"Type": "AWS::EC2::SecurityGroupEgress", "Properties": {
            "GroupId": {"Ref": "AcsSecurityGroup"}, "DestinationSecurityGroupId": {"Ref": "RcsAsSecurityGroup"},
            "IpProtocol": "tcp", "FromPort": 5060, "ToPort": 5060}})
        self.assertProblem(t, "AcsSecurityGroup egress to RcsAsSecurityGroup port 5060 has no matching matrix entry")

    def test_a_listener_on_another_port_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["MsrpTlsListener"]["Properties"]["Port"] = 8443
        self.assertProblem(t, "MsrpTlsListener: port 8443 on Nlb is not a client port")

    def test_another_internet_facing_load_balancer_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["Extra"] = copy.deepcopy(t["Resources"]["Alb"])
        self.assertProblem(t, "Extra: internet-facing; only Alb, Nlb may be")

    def test_a_web_acl_without_a_rate_rule_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["WebAcl"]["Properties"]["Rules"] = []
        self.assertProblem(t, "WebAcl: no rate-based rule")

    def test_booleans_written_as_strings_count(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["Task"] = task_definition(Privileged="true", ReadonlyRootFilesystem="false")
        self.assertProblem(t, "Task/svc: privileged")
        self.assertProblem(t, "Task/svc: root file system is not read-only")

    def test_acs_admin_is_not_routed(self):
        rules = check_infra.resources(self.template, "AWS::ElasticLoadBalancingV2::ListenerRule")
        paths = [v for r in rules.values() for c in r["Properties"]["Conditions"] if isinstance(c, dict)
                 for v in c.get("PathPatternConfig", {}).get("Values", [])]
        self.assertFalse([p for p in paths if p.startswith("/admin") or p in ("/*", "*")], paths)
        for name in ("HttpsListener", "HttpListener"):
            actions = str(self.template["Resources"][name]["Properties"]["DefaultActions"])
            self.assertIn("fixed-response", actions)
            self.assertNotIn("AcsTargetGroup", actions)

    def test_rcs_as_reaches_rcs_as_on_sip(self):
        # The group owner's forwarding (#121) is in the matrix, both ways.
        self.assertIn("RcsAsSecurityGroup", check_infra.EXPECTED_INGRESS[("RcsAsSecurityGroup", 5060)])
        t = self.changed(RcsAsToRcsAs=None)
        self.assertProblem(t, "RcsAsSecurityGroup port 5060: RcsAsSecurityGroup is missing")

    def test_the_nlb_reaches_pcscf_on_5061_only(self):
        t = self.changed(Old=ingress("PcscfSecurityGroup", 5060, SourceSecurityGroupId={"Ref": "NlbSecurityGroup"}))
        self.assertProblem(t, "PcscfSecurityGroup port 5060: NlbSecurityGroup is not in the ADR 0007 matrix")

    def test_the_nlb_addresses_are_fixed_and_retained(self):
        mappings = self.template["Resources"]["Nlb"]["Properties"]["SubnetMappings"]
        self.assertEqual(len(mappings), 2)
        for m in mappings:
            eip = m["AllocationId"]["Fn::If"][1]["Fn::GetAtt"][0]
            self.assertEqual(self.template["Resources"][eip].get("DeletionPolicy"), "Retain")

    def test_the_http_listener_forwarding_with_a_certificate_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["HttpListener"]["Properties"]["DefaultActions"] = [
            {"Type": "forward", "TargetGroupArn": {"Ref": "AcsTargetGroup"}}]
        self.assertProblem(t, "HttpListener: the HTTP listener acts the same with a certificate")

    def test_a_rule_on_the_http_listener_with_a_certificate_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["AcsConfigRule"]["Properties"]["ListenerArn"] = {"Ref": "HttpListener"}
        self.assertProblem(t, "AcsConfigRule: forwards on the HTTP listener even with a certificate")

    def test_a_conditional_listener_protocol_is_refused_not_crashed(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["MsrpTlsListener"]["Properties"]["Protocol"] = {"Fn::If": ["IsDev", "TCP", "TLS"]}
        self.assertProblem(t, "MsrpTlsListener: the protocol must be literal")

    def test_a_task_role_with_managed_policies_is_refused(self):
        t = self.changed(SvcTask=task_definition(), SvcTaskRole=role("dynamodb:GetItem"))
        t["Resources"]["SvcTaskRole"]["Properties"]["ManagedPolicyArns"] = ["arn:aws:iam::aws:policy/SecretsManagerReadWrite"]
        self.assertProblem(t, "SvcTaskRole: a task role has managed policies")

    def test_new_nlb_addresses_are_retained_and_given_ones_reused(self):
        for name in ("NlbAddressA", "NlbAddressB"):
            self.assertEqual(self.template["Resources"][name].get("DeletionPolicy"), "Retain")
        mapping = self.template["Resources"]["Nlb"]["Properties"]["SubnetMappings"][0]["AllocationId"]
        self.assertEqual(mapping, {"Fn::If": ["NewNlbAddressA", {"Fn::GetAtt": ["NlbAddressA", "AllocationId"]},
                                              {"Ref": "NlbAllocationIdA"}]})
        pattern = self.template["Parameters"]["NlbAllocationIdA"]["AllowedPattern"]
        self.assertTrue(re.fullmatch(pattern, "eipalloc-0abc123"))
        self.assertTrue(re.fullmatch(pattern, ""))
        self.assertFalse(re.fullmatch(pattern, "203.0.113.7"))

    def test_an_nlb_allocation_without_its_address_is_refused(self):
        t = copy.deepcopy(self.template)
        del t["Rules"]["NlbAddressPairB"]
        self.assertProblem(t, "Rules: nothing asserts NlbAllocationIdB and NlbReusedAddressB come together")
        t = copy.deepcopy(self.template)
        t["Rules"]["NlbAddressPairA"]["Assertions"][0]["Assert"]["Fn::Or"].pop()
        self.assertProblem(t, "Rules: nothing asserts NlbAllocationIdA and NlbReusedAddressA come together")
        t = copy.deepcopy(self.template)
        del t["Rules"]["NlbAllocationsDistinct"]
        self.assertProblem(t, "Rules: nothing asserts NlbAllocationIdA and NlbAllocationIdB differ")

    def test_an_alb_without_waf_is_refused(self):
        t = self.changed(WebAclAssociation=None)
        self.assertProblem(t, "Alb: internet-facing ALB without an AWS WAF web ACL")

    def test_task_definitions_must_be_locked_down(self):
        for container, fragment in [
            ({"ReadonlyRootFilesystem": False}, "root file system is not read-only"),
            ({"Privileged": True}, "privileged"),
            ({"LinuxParameters": {"Capabilities": {"Drop": []}}}, "does not drop all Linux capabilities"),
            ({"LinuxParameters": {"Capabilities": {"Drop": ["ALL"], "Add": ["NET_ADMIN"]}}}, "adds Linux capabilities"),
        ]:
            with self.subTest(fragment=fragment):
                t = self.changed(SvcTask=task_definition(**container), SvcTaskRole=role("dynamodb:GetItem"))
                self.assertProblem(t, fragment)
        t = self.changed(SvcTask=task_definition(), SvcTaskRole=role("dynamodb:GetItem"))
        self.assertEqual(not_listing(check_infra.problems(t)), [])

    def test_ecs_exec_is_refused(self):
        t = self.changed(Svc={"Type": "AWS::ECS::Service", "Properties": {"EnableExecuteCommand": True}})
        self.assertProblem(t, "Svc: ECS Exec is enabled")

    def test_a_table_without_pitr_is_refused(self):
        t = self.changed(Files={"Type": "AWS::DynamoDB::Table", "Properties": {}})
        self.assertProblem(t, "Files: point-in-time recovery is off")
        t = self.changed(Files={"Type": "AWS::DynamoDB::Table", "Properties": {
            "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True}}})
        self.assertProblem(t, "Files: SSE with a KMS key is not on")
        t = self.changed(Files={"Type": "AWS::DynamoDB::Table", "Properties": {
            "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
            "SSESpecification": {"SSEEnabled": True}}})
        self.assertEqual(not_listing(check_infra.problems(t)), [])

    def test_task_roles_cannot_read_secrets(self):
        for actions in [("secretsmanager:GetSecretValue",), ("SecretsManager:*",), ("*",)]:
            with self.subTest(actions=actions):
                t = self.changed(SvcTask=task_definition(), SvcTaskRole=role(*actions))
                self.assertProblem(t, "SvcTaskRole: a task role may read secrets")
        t = self.changed(SvcTask=task_definition(), SvcTaskRole=role("dynamodb:GetItem"), Extra={
            "Type": "AWS::IAM::Policy",
            "Properties": {"Roles": [{"Ref": "SvcTaskRole"}], "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}},
        })
        self.assertProblem(t, "Extra: lets a task role read secrets")
        td = task_definition()
        td["Properties"]["ExecutionRoleArn"] = {"Fn::GetAtt": ["SvcTaskRole", "Arn"]}
        t = self.changed(SvcTask=td, SvcTaskRole=role("dynamodb:GetItem"))
        self.assertProblem(t, "the task role is also the execution role")


class PlatformServices(TemplateCase):
    """Policies on the service blocks: task definitions, roles, tables."""

    def test_every_service_task_definition_is_present_and_locked_down(self):
        tds = check_infra.resources(self.template, "AWS::ECS::TaskDefinition")
        self.assertEqual(set(tds), {"HssTaskDefinition", "FtServerTaskDefinition", "RelayTaskDefinition", "AcsTaskDefinition"})
        self.assertEqual(check_infra.check_tasks(self.template), [])

    def test_only_the_relay_reads_the_bindings(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["HssTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": {"Fn::GetAtt": ["MsrpBindingsTable", "Arn"]}})
        self.assertProblem(t, "HssTaskRole: may read MsrpBindingsTable; only MsrpRelayTaskRole may")

    def test_a_wildcard_read_reaches_the_bindings_too(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["AcsTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Action": ["dynamodb:Scan"], "Resource": "*"})
        self.assertProblem(t, "AcsTaskRole: may read MsrpBindingsTable")

    def test_nobody_exports_the_bindings(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["MsrpRelayTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Action": "dynamodb:ExportTableToPointInTime",
             "Resource": {"Fn::Sub": "${MsrpBindingsTable.Arn}"}})
        self.assertProblem(t, "MsrpRelayTaskRole: may export MsrpBindingsTable")

    def test_every_table_keeps_pitr(self):
        t = copy.deepcopy(self.template)
        del t["Resources"]["SubscribersTable"]["Properties"]["PointInTimeRecoverySpecification"]
        self.assertProblem(t, "SubscribersTable: point-in-time recovery is off")

    def test_only_rcs_as_reads_the_messages(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["FtServerTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Action": "dynamodb:Query",
             "Resource": {"Fn::Sub": "${MessagesTable.Arn}/index/expiry"}})
        self.assertProblem(t, "FtServerTaskRole: may read MessagesTable; only RcsAsTaskRole may")

    def hss_container(self, t: dict) -> dict:
        return t["Resources"]["HssTaskDefinition"]["Properties"]["ContainerDefinitions"][0]

    def set_start_timeout(self, t: dict, value: str):
        for e in self.hss_container(t)["Environment"]:
            if e["Name"] == "HSS_START_TIMEOUT":
                e["Value"] = value

    def test_the_hss_health_check_outlasts_its_start_timeout(self):
        t = copy.deepcopy(self.template)
        self.set_start_timeout(t, "2m")
        self.assertProblem(t, "StartPeriod + Interval x Retries (105 s) must exceed HSS_START_TIMEOUT (120 s)")

    def test_the_hss_start_timeout_stays_within_what_ecs_can_wait(self):
        t = copy.deepcopy(self.template)
        self.set_start_timeout(t, "4m30s")
        self.hss_container(t)["HealthCheck"]["StartPeriod"] = 300
        self.assertProblem(t, "HSS_START_TIMEOUT is over 240 s")

    def test_an_unreadable_start_timeout_is_refused(self):
        t = copy.deepcopy(self.template)
        self.set_start_timeout(t, "1.5m")
        self.assertProblem(t, "HSS_START_TIMEOUT is not a duration")
    def test_an_arn_wildcard_reaches_the_bindings(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["HssTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Action": "dynamodb:GetItem",
             "Resource": {"Fn::Sub": "arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/*"}})
        self.assertProblem(t, "HssTaskRole: may read MsrpBindingsTable")

    def test_an_arn_naming_the_bindings_table_reaches_it(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["AcsTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Action": "dynamodb:Query",
             "Resource": {"Fn::Sub": "arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${AWS::StackName}-msrp-bindings"}})
        self.assertProblem(t, "AcsTaskRole: may read MsrpBindingsTable")

    def test_a_wildcard_under_a_named_table_stays_there(self):
        targets = check_infra._names({"Fn::Sub": "${SubscribersTable.Arn}/index/*"})
        self.assertEqual(targets, {"SubscribersTable"})

    def test_a_role_without_an_action_its_code_calls_is_refused(self):
        # The #70 blocker: hss Scans profile-index at every start with a KMS key.
        t = copy.deepcopy(self.template)
        statements = t["Resources"]["HssTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        for st in statements:
            if "dynamodb:Scan" in st["Action"]:
                st["Action"] = [a for a in st["Action"] if a != "dynamodb:Scan"]
        self.assertProblem(t, "HssTaskRole: lacks dynamodb:Scan on SubscribersTable/index/profile-index")

    def test_a_grant_on_the_wrong_resource_does_not_count(self):
        required = {"FtServerTaskRole": {"FilesBucket": ["s3:GetObject"]}}
        self.assertIn("FtServerTaskRole: lacks s3:GetObject on FilesBucket, which its code calls",
                      check_infra.check_required_actions(self.template, required))

    def test_a_wildcard_grant_is_refused_even_where_it_covers_the_need(self):
        t = copy.deepcopy(self.template)
        for st in t["Resources"]["HssTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]:
            if st["Resource"] == {"Fn::Sub": "${SubscribersTable.Arn}/index/profile-index"}:
                st["Action"] = ["dynamodb:*"]
        found = check_infra.check_required_actions(t)
        self.assertIn("HssTaskRole: grants the pattern dynamodb:*; list the actions its code calls", found)
        self.assertNotIn("HssTaskRole: lacks dynamodb:Query on SubscribersTable/index/profile-index, which its code calls", found)

    def test_an_action_the_code_does_not_call_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["HssTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Action": "dynamodb:DeleteTable", "Resource": {"Fn::GetAtt": ["SubscribersTable", "Arn"]}})
        self.assertProblem(t, "HssTaskRole: grants dynamodb:deletetable on SubscribersTable, which task-role-actions.yaml does not list")
        t = copy.deepcopy(self.template)
        t["Resources"]["FtServerTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Action": "s3:PutBucketPolicy", "Resource": {"Fn::GetAtt": ["FilesBucket", "Arn"]}})
        self.assertProblem(t, "FtServerTaskRole: grants s3:putbucketpolicy on FilesBucket")

    def test_a_task_role_missing_from_the_table_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["SpareTaskRole"] = copy.deepcopy(t["Resources"]["MsrpRelayTaskRole"])
        self.assertProblem(t, "SpareTaskRole: a task role missing from task-role-actions.yaml")

    def test_a_task_role_without_a_task_definition_is_still_checked(self):
        t = copy.deepcopy(self.template)
        role = copy.deepcopy(t["Resources"]["MsrpRelayTaskRole"])
        role["Properties"]["Policies"][0]["PolicyDocument"]["Statement"] = [
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]
        t["Resources"]["FutureTaskRole"] = role
        self.assertProblem(t, "FutureTaskRole: a task role may read secrets")

    def test_a_secret_grant_inside_a_condition_is_seen(self):
        t = copy.deepcopy(self.template)
        policies = t["Resources"]["AcsTaskRole"]["Properties"]["Policies"]
        policies.append({"Fn::If": ["UseAcsAwsSms", {"PolicyName": "x", "PolicyDocument": {"Statement": [
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}}, {"Ref": "AWS::NoValue"}]})
        self.assertProblem(t, "AcsTaskRole: a task role may read secrets")

    def test_a_service_task_role_reading_its_secrets_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["FtServerTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": {"Ref": "FtNonceKey"}})
        self.assertProblem(t, "FtServerTaskRole: a task role may read secrets")



class Parameters(TemplateCase):
    """Parameter constraints that save a deployment that would fail later."""

    def vpc_cidr_allowed(self, value: str) -> bool:
        # CloudFormation matches AllowedPattern as a Java regex; this pattern
        # uses nothing Java and Python read differently.
        return re.fullmatch(self.template["Parameters"]["VpcCidr"]["AllowedPattern"], value) is not None

    def test_the_vpc_is_rfc_1918_space(self):
        for value in ("10.30.0.0/16", "10.0.0.0/16", "10.255.0.0/16", "172.16.0.0/16", "172.31.0.0/16", "192.168.0.0/16"):
            self.assertTrue(self.vpc_cidr_allowed(value), value)

    def test_other_ranges_are_refused(self):
        # 100.64.0.0/16 is shared address space (RFC 6598): the internal
        # dialer refuses it, so every HSS lookup would fail (#112).
        for value in ("100.64.0.0/16", "198.18.0.0/16", "8.8.0.0/16", "999.1.0.0/16", "172.32.0.0/16",
                      "172.15.0.0/16", "10.256.0.0/16", "192.169.0.0/16", "10.30.1.0/16", "10.30.0.0/20"):
            self.assertFalse(self.vpc_cidr_allowed(value), value)


class AlarmRules(TemplateCase):
    """docs/architecture.md §8: how alarms read aggregated EMF metrics."""

    def alarm(self, t: dict, name: str) -> dict:
        return t["Resources"][name]["Properties"]

    def test_a_single_evaluation_period_is_refused(self):
        t = copy.deepcopy(self.template)
        self.alarm(t, "FtAuthBackendError")["EvaluationPeriods"] = 1
        self.assertProblem(t, "FtAuthBackendError: EvaluationPeriods must be 2 or more")

    def test_a_period_under_a_minute_is_refused(self):
        t = copy.deepcopy(self.template)
        self.alarm(t, "HssLockBusy")["Metrics"][0]["MetricStat"]["Period"] = 10
        self.assertProblem(t, "HssLockBusy: a period is under 60 s")

    def test_missing_data_must_be_stated(self):
        t = copy.deepcopy(self.template)
        del self.alarm(t, "AcsOtpVolume")["TreatMissingData"]
        self.assertProblem(t, "AcsOtpVolume: TreatMissingData is not set")

    def test_a_missing_count_is_zero(self):
        t = copy.deepcopy(self.template)
        self.alarm(t, "RelayStoreErrors")["TreatMissingData"] = "missing"
        self.assertProblem(t, "RelayStoreErrors: a count treats missing data as missing")

    def test_a_missing_gauge_is_not_zero(self):
        t = copy.deepcopy(self.template)
        self.alarm(t, "RelayConnectionsNearLimit")["TreatMissingData"] = "notBreaching"
        self.assertProblem(t, "RelayConnectionsNearLimit: a gauge or latency treats missing data as notBreaching")

    def test_a_timings_sample_count_is_refused(self):
        t = copy.deepcopy(self.template)
        stat = self.alarm(t, "FtSweepStalled")["Metrics"][0]["MetricStat"]
        stat["Metric"]["MetricName"], stat["Stat"] = "sweep.duration", "SampleCount"
        self.assertProblem(t, "FtSweepStalled: statistic SampleCount on a service metric")


class TableKeys(TemplateCase):
    def test_the_scscf_tables_use_the_stacks_key(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["AuthChallengesTable"]["Properties"]["SSESpecification"] = {"SSEEnabled": True}
        self.assertProblem(t, "AuthChallengesTable: not encrypted with a customer-managed key of the stack")

    def test_only_scscf_reads_its_state(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["HssTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Action": "dynamodb:Scan", "Resource": {"Fn::GetAtt": ["RegistrationsTable", "Arn"]}})
        self.assertProblem(t, "HssTaskRole: may read RegistrationsTable; only ScscfTaskRole may")


class StackAdditions(TemplateCase):
    """Bad copies of what #126 adds: endpoints, S-CSCF state, top-level alarms."""

    def test_https_to_the_internet_with_endpoints_on_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["HssSecurityGroup"]["Properties"]["SecurityGroupEgress"].append(
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "0.0.0.0/0"})
        self.assertProblem(t, "HssSecurityGroup: sends to 0.0.0.0/0 port 443 even with interface endpoints")

    def test_ft_server_reaching_anything_else_is_refused(self):
        t = self.changed(Extra={"Type": "AWS::EC2::SecurityGroupEgress", "Properties": {
            "GroupId": {"Ref": "FtServerSecurityGroup"}, "DestinationSecurityGroupId": {"Ref": "AcsSecurityGroup"},
            "IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080}})
        self.assertProblem(t, "FtServerSecurityGroup: may send to sg AcsSecurityGroup port 8080")

    def test_a_scan_on_the_scscf_tables_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["ScscfStatePolicy"]["Properties"]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Action": "dynamodb:Scan", "Resource": {"Fn::GetAtt": ["RegistrationsTable", "Arn"]}})
        self.assertProblem(t, "ScscfStatePolicy: may Scan RegistrationsTable")

    def test_the_scscf_key_used_by_the_account_is_refused(self):
        t = copy.deepcopy(self.template)
        for st in t["Resources"]["ScscfStateKey"]["Properties"]["KeyPolicy"]["Statement"]:
            if st.get("Sid") == "DeployerCreatesTablesThroughDynamoDb":
                del st["Condition"]["StringEquals"]["aws:PrincipalArn"]
        self.assertProblem(t, "ScscfStateKey: root may use the key")

    def test_an_scscf_table_under_another_key_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["RegistrationsTable"]["Properties"]["SSESpecification"]["KMSMasterKeyId"] = "alias/aws/dynamodb"
        self.assertProblem(t, "RegistrationsTable: not encrypted with a customer-managed key of the stack")

    def test_top_level_metric_alarms_follow_the_rules_too(self):
        t = copy.deepcopy(self.template)
        props = t["Resources"]["AcsOtpVolume"]["Properties"]
        props["Period"], props["Statistic"] = 30, "Average"
        self.assertProblem(t, "AcsOtpVolume: a period is under 60 s")
        self.assertProblem(t, "AcsOtpVolume: statistic Average on a service metric")

    def test_a_gauge_alarm_filling_missing_data_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["PcscfTransactionBytes"]["Properties"]["TreatMissingData"] = "notBreaching"
        self.assertProblem(t, "PcscfTransactionBytes: a gauge or latency treats missing data as notBreaching")

    def test_rcs_as_may_check_conditions_on_its_messages(self):
        self.assertEqual(check_infra.check_required_actions(self.template), [])
        t = copy.deepcopy(self.template)
        for st in t["Resources"]["RcsAsTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]:
            if isinstance(st.get("Action"), list) and "dynamodb:ConditionCheckItem" in st["Action"] and \
                    st["Resource"] == {"Fn::GetAtt": ["MessagesTable", "Arn"]}:
                st["Action"].remove("dynamodb:ConditionCheckItem")
        self.assertProblem(t, "RcsAsTaskRole: lacks dynamodb:ConditionCheckItem on MessagesTable")

    def test_only_rcs_as_reads_the_groups(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["AcsTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": {"Fn::GetAtt": ["GroupChatsTable", "Arn"]}})
        self.assertProblem(t, "AcsTaskRole: may read GroupChatsTable; only RcsAsTaskRole may")

    def test_every_endpoint_is_held_to_this_account(self):
        t = copy.deepcopy(self.template)
        del t["Resources"]["DynamoDbEndpoint"]["Properties"]["PolicyDocument"]
        self.assertProblem(t, "DynamoDbEndpoint: no endpoint policy")
        t = copy.deepcopy(self.template)
        st = t["Resources"]["LogsEndpoint"]["Properties"]["PolicyDocument"]["Statement"][0]
        del st["Condition"]
        self.assertProblem(t, "LogsEndpoint: an endpoint policy statement not held to this account")
        t = copy.deepcopy(self.template)
        t["Resources"]["S3Endpoint"]["Properties"]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::someone-else/*"})
        self.assertProblem(t, "S3Endpoint: an endpoint policy statement not held to this account")

    def test_services_wait_for_the_endpoints(self):
        for name in ("HssService", "FtServerService", "RelayService", "AcsService"):
            depends = self.template["Resources"][name]["DependsOn"]
            self.assertIn("EndpointsReady", [depends] if isinstance(depends, str) else depends, name)

    def test_without_nat_the_endpoints_are_required(self):
        rule = self.template["Rules"]["NoNatNeedsEndpoints"]
        self.assertEqual(rule["RuleCondition"], {"Fn::Equals": [{"Ref": "NatGateways"}, "none"]})
        for name in ("NatGatewayA", "NatAddressA", "PrivateDefaultRouteA", "PrivateDefaultRouteB"):
            self.assertEqual(self.template["Resources"][name].get("Condition"), "HasNat")

    def test_ft_server_must_reach_the_hss(self):
        t = self.changed(FtServerToHssApiOut=None)
        self.assertProblem(t, "FtServerSecurityGroup: cannot reach sg HssSecurityGroup port 8081")

    def test_a_separate_egress_to_the_internet_is_refused(self):
        t = self.changed(Wide={"Type": "AWS::EC2::SecurityGroupEgress", "Properties": {
            "GroupId": {"Ref": "AcsSecurityGroup"}, "CidrIp": "0.0.0.0/0", "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443}})
        self.assertProblem(t, "AcsSecurityGroup: sends to 0.0.0.0/0 even with interface endpoints")

    def test_registrations_expire_on_ttl_not_on_the_index_key(self):
        spec = self.template["Resources"]["RegistrationsTable"]["Properties"]["TimeToLiveSpecification"]
        self.assertEqual(spec, {"AttributeName": "ttl", "Enabled": True})



class FailClosed(TemplateCase):
    """The five bypass copies of the second reviews, and QA's minors."""

    def statements(self, t: dict, role: str) -> list:
        return t["Resources"][role]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]

    def test_an_extra_action_on_a_resource_written_with_if_is_refused(self):
        t = copy.deepcopy(self.template)
        self.statements(t, "FtServerTaskRole").append({"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": {
            "Fn::If": ["IsDev", {"Fn::Sub": "${FilesBucket.Arn}/*"}, {"Ref": "AWS::NoValue"}]}})
        self.assertProblem(t, "FtServerTaskRole: Resource written with a function the checks cannot read")

    def test_an_extra_action_on_a_resource_written_with_join_is_refused(self):
        t = copy.deepcopy(self.template)
        self.statements(t, "FtServerTaskRole").append({"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": {
            "Fn::Join": ["", [{"Fn::GetAtt": ["FilesBucket", "Arn"]}, "/*"]]}})
        self.assertProblem(t, "FtServerTaskRole: Resource written with a function the checks cannot read")

    def test_a_secret_read_inside_a_nested_if_is_refused(self):
        t = copy.deepcopy(self.template)
        self.statements(t, "HssTaskRole").append({"Fn::If": ["IsDev", {"Fn::If": ["IsProduction", {
            "Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": {"Ref": "HssAdminToken"}},
            {"Ref": "AWS::NoValue"}]}, {"Ref": "AWS::NoValue"}]})
        self.assertProblem(t, "HssTaskRole: a statement inside a nested Fn::If")

    def test_an_if_in_a_resource_is_refused(self):
        t = copy.deepcopy(self.template)
        self.statements(t, "MsrpRelayTaskRole")[0]["Resource"] = {
            "Fn::If": ["IsDev", {"Fn::GetAtt": ["MsrpBindingsTable", "Arn"]}, "*"]}
        self.assertProblem(t, "MsrpRelayTaskRole: Resource written with a function the checks cannot read")

    def test_an_import_on_a_task_role_is_refused(self):
        t = copy.deepcopy(self.template)
        self.statements(t, "AcsTaskRole").append({"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": {
            "Fn::ImportValue": "someone-elses-table-arn"}})
        self.assertProblem(t, "AcsTaskRole: Resource written with a function the checks cannot read")

    def test_the_registry_imports_stay_allowed_in_execution_roles(self):
        self.assertEqual([p for p in check_infra.check_iam_shapes(self.template)], [])

    def test_the_sns_deny_must_cover_every_topic_exactly(self):
        t = copy.deepcopy(self.template)
        for p in t["Resources"]["AcsTaskRole"]["Properties"]["Policies"]:
            if isinstance(p, dict) and "Fn::If" in p and p["Fn::If"][0] == "UseAcsSns":
                p["Fn::If"][1]["PolicyDocument"]["Statement"][1]["Resource"] = {
                    "Fn::Sub": "arn:${AWS::Partition}:sns:*:*:*-not-every-topic"}
        self.assertProblem(t, "AcsTaskRole: sns:Publish on '*' without a Deny on topics")

    def http_rules(self, t: dict):
        return t["Resources"]["HttpListener"]["Properties"]["DefaultActions"][0]["Fn::If"]

    def test_the_http_listener_condition_must_be_the_certificate(self):
        t = copy.deepcopy(self.template)
        self.http_rules(t)[0] = "IsDev"
        self.assertProblem(t, "HttpListener: with a certificate the HTTP listener must redirect to HTTPS")
        t = copy.deepcopy(self.template)
        self.http_rules(t)[1] = {"Type": "forward", "TargetGroupArn": {"Ref": "AcsTargetGroup"}}
        self.assertProblem(t, "HttpListener: with a certificate the HTTP listener must redirect to HTTPS")

    def test_a_rule_whose_if_picks_the_http_listener_with_a_certificate_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["FtServerRule"]["Properties"]["ListenerArn"] = {
            "Fn::If": ["HasAlbCertificate", {"Ref": "HttpListener"}, {"Ref": "HttpsListener"}]}
        self.assertProblem(t, "FtServerRule: forwards on the HTTP listener even with a certificate")
        t = copy.deepcopy(self.template)
        t["Resources"]["FtServerRule"]["Properties"]["ListenerArn"] = {
            "Fn::If": ["IsDev", {"Ref": "HttpsListener"}, {"Ref": "HttpListener"}]}
        self.assertProblem(t, "FtServerRule: forwards on the HTTP listener even with a certificate")

    def test_a_topic_key_needs_both_generate_and_decrypt(self):
        t = copy.deepcopy(self.template)
        for st in t["Resources"]["AlarmKey"]["Properties"]["KeyPolicy"]["Statement"]:
            if st.get("Sid") == "PublishersEncrypt":
                st["Action"] = ["kms:GenerateDataKey*"]
        self.assertProblem(t, "AlarmTopic: cloudwatch.amazonaws.com publishes to it but cannot use its key AlarmKey")

    def test_discover_instances_needs_both_halves_of_its_condition(self):
        for half in ("servicediscovery:ServiceName", "servicediscovery:NamespaceName"):
            with self.subTest(half=half):
                t = copy.deepcopy(self.template)
                st = [s for s in t["Resources"]["IcscfTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
                      if s.get("Action") == "servicediscovery:DiscoverInstances"][0]
                del st["Condition"]["StringEquals"][half]
                self.assertProblem(t, "IcscfTaskRole: DiscoverInstances without the condition")

    def test_a_dns_label_over_63_characters_is_refused(self):
        pattern = self.template["Parameters"]["FtHostName"]["AllowedPattern"]
        self.assertTrue(re.fullmatch(pattern, "a" * 63 + ".example.com"))
        self.assertFalse(re.fullmatch(pattern, "a" * 64 + ".example.com"))


RUNBOOK = TEMPLATE.parent.parent / "docs" / "runbook.md"


class AlarmRunbook(TemplateCase):
    """Every alarm sends whoever is paged to its own runbook section."""

    def anchors(self) -> set[str]:
        return check_infra.runbook_anchors(str(RUNBOOK))

    def test_the_runbook_has_a_section_for_every_alarm(self):
        self.assertEqual(check_infra.check_runbook(self.template, self.anchors()), [])

    def test_an_alarm_without_a_link_is_refused(self):
        t = copy.deepcopy(self.template)
        del t["Resources"]["FtAuthBackendError"]["Properties"]["AlarmDescription"]
        self.assertIn("FtAuthBackendError: the description must link docs/runbook.md#ftauthbackenderror",
                      " ".join(check_infra.check_runbook(t, self.anchors())))

    def test_a_link_to_another_alarms_section_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["HssLockBusy"]["Properties"]["AlarmDescription"] = "See docs/runbook.md#hsscxerrors."
        self.assertIn("HssLockBusy: the description must link docs/runbook.md#hsslockbusy",
                      " ".join(check_infra.check_runbook(t, self.anchors())))

    def test_a_missing_section_is_refused(self):
        anchors = self.anchors() - {"relaystoreerrors"}
        self.assertEqual(check_infra.check_runbook(self.template, anchors),
                         ["RelayStoreErrors: docs/runbook.md has no section RelayStoreErrors"])
class SecurityChecklist(TemplateCase):
    """Bad copies of the template that the security review asked to fail."""

    def statements(self, t: dict, role: str, policy: int = 0) -> list:
        return t["Resources"][role]["Properties"]["Policies"][policy]["PolicyDocument"]["Statement"]

    def test_a_glob_read_on_every_table_reaches_the_bindings(self):
        t = copy.deepcopy(self.template)
        self.statements(t, "HssTaskRole").append({"Effect": "Allow", "Action": "dynamodb:Get*", "Resource": {
            "Fn::Sub": "arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/*"}})
        self.assertProblem(t, "HssTaskRole: may read MsrpBindingsTable")

    def test_not_action_is_refused(self):
        t = copy.deepcopy(self.template)
        self.statements(t, "AcsTaskRole").append({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
        self.assertProblem(t, "AcsTaskRole: an Allow with NotAction grants everything it does not name")
        self.assertProblem(t, "AcsTaskRole: a task role may read secrets")

    def test_an_execution_role_reading_every_secret_is_refused(self):
        t = copy.deepcopy(self.template)
        for st in self.statements(t, "FtServerExecutionRole"):
            if st.get("Action") == "secretsmanager:GetSecretValue":
                st["Resource"] = "*"
        self.assertProblem(t, "FtServerExecutionRole: may read *, which its task definition does not inject")

    def test_an_execution_role_reading_another_services_secret_is_refused(self):
        t = copy.deepcopy(self.template)
        for st in self.statements(t, "RelayExecutionRole"):
            if st.get("Action") == "secretsmanager:GetSecretValue":
                st["Resource"] = st["Resource"] + [{"Ref": "HssAdminToken"}]
        self.assertProblem(t, "RelayExecutionRole: may read HssAdminToken")

    def test_parameter_store_secrets_count_as_secrets(self):
        t = copy.deepcopy(self.template)
        self.statements(t, "HssTaskRole").append({"Effect": "Allow", "Action": "ssm:GetParameter*", "Resource": {
            "Fn::Sub": "arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter/x"}})
        self.assertProblem(t, "HssTaskRole: a task role may read secrets")

    def test_a_separate_role_policy_is_seen(self):
        t = self.changed(Extra={"Type": "AWS::IAM::RolePolicy", "Properties": {
            "RoleName": {"Ref": "AcsTaskRole"}, "PolicyName": "x", "PolicyDocument": {"Statement": [
                {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": {"Ref": "AcsAdminToken"}}]}}})
        self.assertProblem(t, "Extra: lets a task role read secrets")

    def test_a_secret_resource_policy_for_a_task_role_is_refused(self):
        t = self.changed(Open={"Type": "AWS::SecretsManager::ResourcePolicy", "Properties": {
            "SecretId": {"Ref": "FtNonceKey"}, "ResourcePolicy": {"Statement": [{
                "Effect": "Allow", "Principal": {"AWS": {"Fn::GetAtt": ["FtServerTaskRole", "Arn"]}},
                "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}}})
        self.assertProblem(t, "Open: a secret resource policy lets a task role or anyone read it")

    def test_any_action_on_every_resource_is_refused(self):
        t = copy.deepcopy(self.template)
        self.statements(t, "MsrpRelayTaskRole").append({"Effect": "Allow", "Action": "logs:PutLogEvents", "Resource": "*"})
        self.assertProblem(t, "MsrpRelayTaskRole: logs:PutLogEvents on Resource '*'")

    def test_sns_publish_without_the_topic_deny_is_refused(self):
        t = copy.deepcopy(self.template)
        policies = t["Resources"]["AcsTaskRole"]["Properties"]["Policies"]
        for p in policies:
            if isinstance(p, dict) and "Fn::If" in p and p["Fn::If"][0] == "UseAcsSns":
                p["Fn::If"][1]["PolicyDocument"]["Statement"] = p["Fn::If"][1]["PolicyDocument"]["Statement"][:1]
        self.assertProblem(t, "AcsTaskRole: sns:Publish on '*' without a Deny on topics reaches every topic")

    def test_a_scan_outside_the_allowlist_is_refused(self):
        t = copy.deepcopy(self.template)
        self.statements(t, "AcsTaskRole").append({"Effect": "Allow", "Action": "dynamodb:Scan",
                                                   "Resource": {"Fn::GetAtt": ["AcsTable", "Arn"]}})
        self.assertProblem(t, "AcsTaskRole: may Scan AcsTable")

    def test_the_root_using_a_key_is_refused(self):
        t = copy.deepcopy(self.template)
        statements = t["Resources"]["HssKey"]["Properties"]["KeyPolicy"]["Statement"]
        statements[0]["Action"] = statements[0]["Action"] + ["kms:Create*"]
        self.assertProblem(t, "HssKey: root may use the key; only HssTaskRole may")

    def test_another_role_using_the_hss_key_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["HssKey"]["Properties"]["KeyPolicy"]["Statement"].append({
            "Effect": "Allow", "Principal": {"AWS": {"Fn::GetAtt": ["AcsTaskRole", "Arn"]}},
            "Action": "kms:Decrypt", "Resource": "*"})
        self.assertProblem(t, "HssKey: AcsTaskRole may use the key")

    def test_an_unencrypted_topic_is_refused(self):
        t = copy.deepcopy(self.template)
        del t["Resources"]["AlarmTopic"]["Properties"]["KmsMasterKeyId"]
        self.assertProblem(t, "AlarmTopic: not encrypted (KmsMasterKeyId)")

    def test_a_topic_policy_without_cloudwatch_silences_the_alarms(self):
        t = copy.deepcopy(self.template)
        st = t["Resources"]["AlarmTopicPolicy"]["Properties"]["PolicyDocument"]["Statement"][0]
        st["Principal"]["Service"] = ["events.amazonaws.com"]
        self.assertProblem(t, "AlarmTopic: cloudwatch.amazonaws.com publishes to it but its topic policy does not allow it")

    def test_an_image_by_tag_is_refused(self):
        t = copy.deepcopy(self.template)
        c = t["Resources"]["AcsTaskDefinition"]["Properties"]["ContainerDefinitions"][0]
        c["Image"]["Fn::Sub"][0] = "${Repository}:${AcsImageTag}"
        self.assertProblem(t, "AcsTaskDefinition/acs: image by tag")

    def test_a_secret_resolved_into_the_environment_is_refused(self):
        t = copy.deepcopy(self.template)
        c = t["Resources"]["FtServerTaskDefinition"]["Properties"]["ContainerDefinitions"][0]
        c["Environment"].append({"Name": "LEAK", "Value": "{{resolve:secretsmanager:x}}"})
        self.assertProblem(t, "FtServerTaskDefinition/ft-server: LEAK resolves a secret into plain text")

    def test_buckets_must_be_locked(self):
        t = copy.deepcopy(self.template)
        props = t["Resources"]["FilesBucket"]["Properties"]
        props["PublicAccessBlockConfiguration"]["RestrictPublicBuckets"] = "false"
        del props["BucketEncryption"]
        self.assertProblem(t, "FilesBucket: RestrictPublicBuckets is not on")
        self.assertProblem(t, "FilesBucket: no default encryption")
        t = self.changed(FilesBucketPolicy=None)
        self.assertProblem(t, "FilesBucket: its policy does not refuse requests without TLS")

    def test_a_service_in_another_group_or_subnet_is_refused(self):
        t = copy.deepcopy(self.template)
        net = t["Resources"]["AcsService"]["Properties"]["NetworkConfiguration"]["AwsvpcConfiguration"]
        net["SecurityGroups"].append({"Ref": "HssSecurityGroup"})
        net["AssignPublicIp"] = "ENABLED"
        net["Subnets"] = [{"Ref": "PublicSubnetA"}]
        self.assertProblem(t, "AcsService: runs in ['AcsSecurityGroup', 'HssSecurityGroup']")
        self.assertProblem(t, "AcsService: tasks get a public address")
        self.assertProblem(t, "AcsService: tasks outside the private subnets")



class SecurityChecklistRound3(TemplateCase):
    """Bad copies from the second security and QA reviews."""

    def statements(self, t: dict, role: str) -> list:
        return t["Resources"][role]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]

    def test_a_statement_level_condition_is_seen(self):
        t = copy.deepcopy(self.template)
        self.statements(t, "FtServerTaskRole").append({"Fn::If": ["IsDev", {
            "Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": {"Ref": "FtNonceKey"}},
            {"Ref": "AWS::NoValue"}]})
        self.assertProblem(t, "FtServerTaskRole: a task role may read secrets")

    def test_a_wildcard_arn_is_refused(self):
        t = copy.deepcopy(self.template)
        self.statements(t, "MsrpRelayTaskRole").append(
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::*/*"})
        self.assertProblem(t, "MsrpRelayTaskRole: arn:aws:s3:::*/* is a wildcard ARN")

    def test_the_bucket_objects_wildcard_is_the_one_allowed(self):
        self.assertEqual(check_infra.WILDCARD_ALLOWED, {("FtServerTaskRole", "FilesBucket/*")})

    def test_waf_logs_must_redact(self):
        for field, message in ((0, "WebAcl: WAF logs keep the query string"),
                               (1, "WebAcl: WAF logs keep the authorization header"),
                               (3, "WebAcl: WAF logs keep the x-3gpp-intended-identity header")):
            with self.subTest(field=field):
                t = copy.deepcopy(self.template)
                del t["Resources"]["WafLogging"]["Properties"]["RedactedFields"][field]
                self.assertProblem(t, message)
        t = self.changed(WafLogging=None)
        self.assertProblem(t, "WebAcl: no WAF logging configuration")

    def test_a_publisher_shut_out_of_the_topic_key_is_refused(self):
        t = copy.deepcopy(self.template)
        for st in t["Resources"]["AlarmKey"]["Properties"]["KeyPolicy"]["Statement"]:
            if st.get("Sid") == "PublishersEncrypt":
                st["Principal"]["Service"] = ["events.amazonaws.com", "budgets.amazonaws.com"]
        self.assertProblem(t, "AlarmTopic: cloudwatch.amazonaws.com publishes to it but cannot use its key AlarmKey")

    def test_the_hss_key_keeps_its_encryption_context(self):
        t = copy.deepcopy(self.template)
        for st in t["Resources"]["HssKey"]["Properties"]["KeyPolicy"]["Statement"]:
            st.pop("Condition", None) if st.get("Sid") == "HssWrapsAndUnwraps" else None
        self.assertProblem(t, "HssKey: a use of the key without kms:EncryptionContext:service=hss")

    def test_discover_instances_must_name_the_hss_service(self):
        t = copy.deepcopy(self.template)
        self.statements(t, "AcsTaskRole").append({"Effect": "Allow", "Action": "servicediscovery:DiscoverInstances",
                                                   "Resource": "*"})
        self.assertProblem(t, "AcsTaskRole: DiscoverInstances without the condition holding it to the hss service")

    def test_host_names_are_checked_at_the_parameter(self):
        t = copy.deepcopy(self.template)
        del t["Parameters"]["AcsHostName"]["AllowedPattern"]
        self.assertProblem(t, "parameter AcsHostName: no AllowedPattern")
        t = copy.deepcopy(self.template)
        t["Parameters"]["FtHostName"]["AllowedPattern"] = ".*"
        self.assertProblem(t, "parameter FtHostName: its pattern accepts 'a b'")

    def test_every_read_action_reaches_the_bindings(self):
        for action in ("dynamodb:BatchGetItem", "dynamodb:PartiQLSelect", "dynamodb:GetRecords"):
            with self.subTest(action=action):
                t = copy.deepcopy(self.template)
                self.statements(t, "HssTaskRole").append(
                    {"Effect": "Allow", "Action": action, "Resource": {"Fn::GetAtt": ["MsrpBindingsTable", "Arn"]}})
                self.assertProblem(t, "HssTaskRole: may read MsrpBindingsTable")

    def test_service_impaired_hears_every_failure_of_this_cluster(self):
        pattern = self.template["Resources"]["ServiceImpaired"]["Properties"]["EventPattern"]
        self.assertNotIn("clusterArn", pattern["detail"])
        self.assertIn("prefix", pattern["resources"][0])
        self.assertEqual(set(pattern["detail"]["eventName"]), {
            "SERVICE_TASK_START_IMPAIRED", "SERVICE_TASK_PLACEMENT_FAILURE",
            "SERVICE_TASK_CONFIGURATION_FAILURE", "SERVICE_DEPLOYMENT_FAILED"})


if __name__ == "__main__":
    unittest.main()
