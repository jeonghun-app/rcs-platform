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


if __name__ == "__main__":
    unittest.main()
