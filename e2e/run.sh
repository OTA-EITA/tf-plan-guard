#!/usr/bin/env bash
# End-to-end test: plan a deliberately risky configuration with the real
# Terraform AWS provider (dummy credentials, never applied) and check that
# tf-plan-guard flags it.
set -euo pipefail

bin=${BIN:-$PWD/bin/tf-plan-guard}
dir=e2e/risky

# Dummy credentials: the provider is configured to skip every validation, and
# the plan only contains creates, so no AWS API is ever called.
export AWS_ACCESS_KEY_ID=dummy AWS_SECRET_ACCESS_KEY=dummy

terraform -chdir="$dir" init -input=false -no-color >/dev/null
terraform -chdir="$dir" plan -input=false -refresh=false -no-color -out=plan.tfplan >/dev/null
terraform -chdir="$dir" show -json plan.tfplan > plan.json

fail() { echo "e2e: $*" >&2; exit 1; }

set +e
"$bin" --output json plan.json > result.json
code=$?
set -e
[ "$code" -eq 1 ] || fail "risky plan must exit 1, got $code"

for rule in TF-NET-001 TF-IAM-001 TF-DB-001 TF-S3-001 TF-ENC-001; do
  jq -e --arg r "$rule" '.findings | any(.ruleId == $r)' result.json >/dev/null || fail "$rule was not reported"
done
jq -e '.planSummary.create == 5' result.json >/dev/null || fail "plan summary should count 5 creates"

"$bin" --output markdown plan.json | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}" || true

# Accepting the HIGH findings leaves only the MEDIUM one, which passes the default threshold.
"$bin" --ignore 'TF-NET-001' --ignore 'TF-IAM-001=aws_iam_policy.deployer' \
  --ignore 'TF-DB-001=aws_db_instance.*' --ignore 'TF-S3-001=*' plan.json >/dev/null \
  || fail "ignored findings must not fail the run"

echo "e2e: all expectations met"
