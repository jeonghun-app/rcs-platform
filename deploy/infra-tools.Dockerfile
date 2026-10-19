# Tools for `make infra-lint`: cfn-lint, and Python for the policy checks in
# scripts/check_infra.py, which use cfn-lint's CloudFormation YAML decoder.
# The base image is pinned by digest, and cfn-lint and its dependencies by
# hash (infra-tools.requirements.txt), so CI and a laptop check templates
# with the same rules; update them in their own pull request.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
COPY infra-tools.requirements.txt /tmp/
RUN pip install --no-cache-dir --require-hashes --no-deps -r /tmp/infra-tools.requirements.txt
