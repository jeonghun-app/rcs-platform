# Tools for `make infra-lint`: cfn-lint, and Python for the policy checks in
# scripts/check_infra.py, which use cfn-lint's CloudFormation YAML decoder.
# The base image is pinned by digest, and cfn-lint and its dependencies by
# hash (infra-tools.requirements.txt), so CI and a laptop check templates
# with the same rules; update them in their own pull request.
FROM python:3.15-slim@sha256:94d3426f1def7db4a106a232ac121bfd975393e5dfd40a619b955fae45fe7913
COPY infra-tools.requirements.txt /tmp/
RUN pip install --no-cache-dir --require-hashes --no-deps -r /tmp/infra-tools.requirements.txt
