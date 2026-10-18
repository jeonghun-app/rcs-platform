# Architecture decision records

| ADR | Title | Status |
|---|---|---|
| [0001](0001-go-monorepo-own-protocol-stacks.md) | Go monorepo with every protocol stack written here | accepted |
| [0002](0002-service-decomposition.md) | One service per IMS/RCS functional entity | accepted |
| [0003](0003-aws-topology.md) | ECS Fargate behind an NLB and an ALB, one CloudFormation stack | accepted |
| [0004](0004-msrp-anchoring.md) | MSRP is anchored by a relay that pcscf controls | accepted |
| [0005](0005-shared-state-and-instance-addressing.md) | Shared state in DynamoDB, instance addressing only where a connection lives | accepted |
| [0006](0006-acs-integration.md) | acs stays in its own repository and is deployed from a pinned release | accepted |

New ADRs use `NNNN-kebab-title.md` with the sections Context, Decision, Rationale
and Consequences, and are added to this table.
