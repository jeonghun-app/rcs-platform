"""Tests of scripts/check_infra.py: the real template passes, and each policy
fails on a template changed to break it. Run with
python3 -m unittest discover -s scripts -p 'test_check_infra.py' in the infra
tools image (make infra-lint)."""

from __future__ import annotations

import copy
import pathlib
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

    def test_a_service_task_role_reading_its_secrets_is_refused(self):
        t = copy.deepcopy(self.template)
        t["Resources"]["FtServerTaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": {"Ref": "FtNonceKey"}})
        self.assertProblem(t, "FtServerTaskRole: a task role may read secrets")


if __name__ == "__main__":
    unittest.main()
