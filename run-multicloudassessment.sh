#!/usr/bin/env bash
# ============================================================
# Agentic Multi Cloud Security Assessment Runner - v4.2.3 (fixed)
# Author: Wagner Azevedo
# Created on: 2025-10-22T00:29:00Z
# Changes in this revision:
# - FIX: Removed array expansion causing ---output-formats bug.
# - NEW: Safe eval-based execution for Prowler with fallback.
# - LOG: Adds full command preview before execution.
# - COMPATIBLE: Prowler 3.x → 6.x.
# ============================================================

set -euo pipefail
set +u
export LANG=C.UTF-8

CREATED_AT="2025-10-22T00:29:00Z"
SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_TS=$(date +%s)
VERSION_REV="v4.2.2-(fixed)-$START_TIME"

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Starting Multicloud Assessment Runner $VERSION_REV (created at $CREATED_AT)"

# === Required vars (safe defaults) ===
CLIENT_NAME="${1:-unknown}"
CLOUD_PROVIDER="${2:-unknown}"
ACCOUNT_ID="${3:-undefined}"
set -u

AWS_REGION="${AWS_REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-agentic-mcsp-assessments}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
OUTPUT_DIR="/tmp/output-${SESSION_ID}"
mkdir -p "$OUTPUT_DIR"

# ============================================================
# Logging helper
# ============================================================
log() {
  local LEVEL="${1:-INFO}"
  local MESSAGE="${2:-}"
  local CONTEXT=""
  [[ -n "${CLIENT_NAME:-}" ]] && CONTEXT+="Client:$CLIENT_NAME "
  [[ -n "${CLOUD_PROVIDER:-}" ]] && CONTEXT+="Cloud:$CLOUD_PROVIDER "
  [[ -n "${ACCOUNT_ID:-}" && "$ACCOUNT_ID" != "undefined" ]] && CONTEXT+="Account:$ACCOUNT_ID "
  local TS; TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "[RUNNER:$SESSION_ID] $TS [$LEVEL] ${CONTEXT}${MESSAGE}"
}

aws_cli() { aws --region "$AWS_REGION" "$@"; }

get_ssm_value() {
  local path="$1"
  aws_cli ssm get-parameter --with-decryption --name "${path:-}" \
    --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

# ============================================================
# 🔐 Multi-Cloud Authentication and Scan Execution
# ============================================================
run_prowler_safe() {
  local provider="$1"
  local output_dir="$2"
  local filename="$3"
  local extras="$4"

  PROWLER_VERSION="$(prowler --version 2>/dev/null | head -n1 | tr -d '\r' || echo 'unknown')"
  log "INFO" "🔍 Detected Prowler version: ${PROWLER_VERSION}"

  HELP_OUTPUT="$(prowler $provider -h 2>&1 || true)"
  if echo "$HELP_OUTPUT" | grep -q '\-M'; then
    OUTPUT_FLAG="-M csv html json-asff"
    log "INFO" "🧩 Using modern syntax: '$OUTPUT_FLAG'"
  elif echo "$HELP_OUTPUT" | grep -q 'output-formats'; then
    OUTPUT_FLAG="--output-formats csv html json-asff"
    log "INFO" "🧩 Using legacy syntax: '$OUTPUT_FLAG'"
  else
    OUTPUT_FLAG=""
    log "WARN" "⚠️ No compatible output flag found. Running without explicit formats."
  fi

  COMMAND="prowler ${provider} ${OUTPUT_FLAG} ${extras} \
    --output-filename ${filename} \
    --output-directory ${output_dir} \
    --no-banner \
    --log-level ${LOG_LEVEL}"

  log "INFO" "▶️ Executing: $COMMAND"
  if ! eval "$COMMAND"; then
    log "WARN" "⚠️ Primary syntax failed. Retrying with fallback..."
    if [[ "$OUTPUT_FLAG" == *"--output-formats"* ]]; then
      eval "prowler ${provider} -M csv html json-asff ${extras} --output-filename ${filename} --output-directory ${output_dir} --no-banner --log-level ${LOG_LEVEL}" \
        || log "WARN" "⚠️ Partial failure in fallback mode (-M)."
    else
      eval "prowler ${provider} --output-formats csv html json-asff ${extras} --output-filename ${filename} --output-directory ${output_dir} --no-banner --log-level ${LOG_LEVEL}" \
        || log "WARN" "⚠️ Partial failure in fallback mode (--output-formats)."
    fi
  fi
}

authenticate() {
  case "$CLOUD_PROVIDER" in
  aws)
    log "INFO" "☁️ Starting AWS authentication..."
    ROLE_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/role"
    ROLE_ARN="$(get_ssm_value "$ROLE_PATH")"
    [[ -z "$ROLE_ARN" ]] && { log "ERROR" "❌ Missing Role ARN at $ROLE_PATH"; return 1; }

    log "INFO" "🔑 Assuming role..."
    CREDS_JSON="$(aws sts assume-role \
      --role-arn "$ROLE_ARN" \
      --role-session-name "AgenticMCSP-${SESSION_ID}" \
      --duration-seconds 3600)"

    export AWS_ACCESS_KEY_ID="$(echo "$CREDS_JSON" | jq -r '.Credentials.AccessKeyId')"
    export AWS_SECRET_ACCESS_KEY="$(echo "$CREDS_JSON" | jq -r '.Credentials.SecretAccessKey')"
    export AWS_SESSION_TOKEN="$(echo "$CREDS_JSON" | jq -r '.Credentials.SessionToken')"

    UPDATED_CREDS_JSON=$(jq -n \
      --arg id "$AWS_ACCESS_KEY_ID" \
      --arg secret "$AWS_SECRET_ACCESS_KEY" \
      --arg token "$AWS_SESSION_TOKEN" \
      '{AWS_ACCESS_KEY_ID:$id, AWS_SECRET_ACCESS_KEY:$secret, AWS_SESSION_TOKEN:$token}')

    if ! aws ssm put-parameter \
      --name "/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/access" \
      --value "$UPDATED_CREDS_JSON" \
      --type "SecureString" \
      --overwrite >/dev/null 2>&1; then
      log "WARN" "⚠️ Failed to update STS token in SSM (check permissions)."
    fi

    log "INFO" "✅ AWS authentication successful."

    run_prowler_safe "aws" "$OUTPUT_DIR" "agentic-mcsp-aws-${ACCOUNT_ID}.json" \
      "--compliance aws_well_architected_framework_reliability_pillar_aws \
       aws_well_architected_framework_security_pillar_aws \
       iso27001_2022_aws mitre_attack_aws nist_800_53_revision_5_aws \
       prowler_threatscore_aws soc2_aws"
    ;;

  azure)
    log "INFO" "☁️ Starting Azure authentication..."
    CREDS_PATH="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials/access"
    CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"
    [[ -z "$CREDS_RAW" ]] && { log "ERROR" "❌ No credentials found at $CREDS_PATH"; return 1; }

    CLEAN_JSON="$(echo "$CREDS_RAW" | jq -r 'fromjson? // .')"
    export AZURE_TENANT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_TENANT_ID')"
    export AZURE_CLIENT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_ID')"
    export AZURE_CLIENT_SECRET="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_SECRET')"
    export AZURE_SUBSCRIPTION_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_SUBSCRIPTION_ID')"

    if az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1; then
      log "INFO" "✅ Azure authentication completed."
    else
      log "ERROR" "❌ Azure authentication failed."
      return 1
    fi

    run_prowler_safe "azure" "$OUTPUT_DIR" "agentic-mcsp-azure-${ACCOUNT_ID}.json" \
      "--sp-env-auth --compliance cis_4.0_azure iso27001_2022_azure mitre_attack_azure prowler_threatscore_azure soc2_azure"
    ;;

  gcp)
    log "INFO" "🌍 Starting GCP authentication..."
    CREDS_PATH="/clients/$CLIENT_NAME/gcp/$ACCOUNT_ID/credentials/access"
    CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"
    [[ -z "$CREDS_RAW" ]] && { log "ERROR" "❌ No credentials found for $ACCOUNT_ID"; return 1; }

    TMP_KEY="/tmp/gcp-${ACCOUNT_ID}.json"
    echo "$CREDS_RAW" >"$TMP_KEY"
    export GOOGLE_APPLICATION_CREDENTIALS="$TMP_KEY"

    if gcloud auth activate-service-account --key-file="$TMP_KEY" --quiet; then
      gcloud config set project "$ACCOUNT_ID" --quiet
      log "INFO" "✅ GCP authentication completed."
    else
      log "ERROR" "❌ GCP authentication failed."
      return 1
    fi

    run_prowler_safe "gcp" "$OUTPUT_DIR" "agentic-mcsp-gcp-${ACCOUNT_ID}.json" \
      "--project-id $ACCOUNT_ID --skip-api-check \
       --compliance cis_4.0_gcp iso27001_2022_gcp mitre_attack_gcp prowler_threatscore_gcp soc2_gcp"

    rm -f "$TMP_KEY" || true
    ;;
  esac
}

# ============================================================
# 🚀 Main Execution
# ============================================================
if ! authenticate; then
  log "ERROR" "⚠️ Authentication failed. Aborting."
  exit 1
fi

TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
S3_PATH="s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}/"

log "INFO" "♻️ Reverting credentials for S3 upload..."
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

aws sts get-caller-identity --output text | awk '{print "🆔 Active account for upload:", $3}' || true

log "INFO" "☁️ Uploading reports to ${S3_PATH}"
if aws s3 cp "$OUTPUT_DIR/" "$S3_PATH" --recursive --only-show-errors --acl bucket-owner-full-control; then
  log "INFO" "✅ Reports successfully uploaded to $S3_PATH"
else
  log "WARN" "⚠️ Upload to S3 failed. Check permissions."
fi

END_TS=$(date +%s)
DURATION=$((END_TS - START_TS))
log "INFO" "⏱️ Execution completed in ${DURATION}s."

log "========== 🔍 EXECUTION SUMMARY =========="
log "INFO" "Session ID: $SESSION_ID"
log "INFO" "Client:     $CLIENT_NAME"
log "INFO" "Cloud:      $CLOUD_PROVIDER"
log "INFO" "Account:    $ACCOUNT_ID"
log "INFO" "Region:     $AWS_REGION"
log "INFO" "Output:     $OUTPUT_DIR"
log "INFO" "S3 Path:    $S3_PATH"
log "INFO" "Version:    $VERSION_REV"
log "=========================================="
