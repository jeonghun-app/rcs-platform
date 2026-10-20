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
        self.assertEqual(check_infra.problems(t), [])

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
        self.assertEqual(check_infra.problems(t), [])

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
        self.assertEqual(check_infra.check_required_actions(self.template, required),
                         ["FtServerTaskRole: lacks s3:GetObject on FilesBucket, which its code calls"])

    def test_a_wildcard_grant_counts(self):
        required = {"HssTaskRole": {"SubscribersTable/index/profile-index": ["dynamodb:Query"]}}
        t = copy.deepcopy(self.template)
        for st in t["Resources"]["HssTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]:
            if st["Resource"] == {"Fn::Sub": "${SubscribersTable.Arn}/index/profile-index"}:
                st["Resource"], st["Action"] = {"Fn::Sub": "${SubscribersTable.Arn}/index/*"}, ["dynamodb:*"]
        self.assertEqual(check_infra.check_required_actions(t, required), [])

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


if __name__ == "__main__":
    unittest.main()
