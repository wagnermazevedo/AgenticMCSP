#!/usr/bin/env bash
# ============================================================
# Multi Cloud Security Assessment Runner - v4.1.6-rev2 (fixed)
# Author: Wagner Azevedo
# Created on: 2025-10-17T00:29:00Z
# Changes in this revision:
# - FIX: Variable protection in the log() function to prevent 'unbound variable' (set -u).
# - Simplified and more robust argument logic.
# ==============================================================

set -euo pipefail
# We keep set -u disabled ONLY for handling initial arguments.
set +u
export LANG=C.UTF-8

CREATED_AT="2025-10-16T00:29:00Z"
SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_TS=$(date +%s)

VERSION_REV="v4.1.6-rev2-$START_TIME"

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Starting the Multicloud Assessment Runner run $VERSION_REV (created in $CREATED_AT)"

# === Mandatory Variable Handling and Assignment (More Robust) ===
# If the argument does not exist, it assumes the default value.
# This is safe because set -u is off (+u).

CLIENT_NAME="${1:-unknown}"
CLOUD_PROVIDER="${2:-unknown}"
ACCOUNT_ID="${3:-undefined}"

# Re-enable strict mode for the remainder of the script
# The '$2: unbound variable' error will no longer occur here since $2 (CLOUD_PROVIDER) has been defined.
set -u

AWS_REGION="${AWS_REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-agentic-mcsp-assessments}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

OUTPUT_DIR="/tmp/output-${SESSION_ID}"
mkdir -p "$OUTPUT_DIR"

# === Logging Helper (UNBOUND VARIABLE FIX) ===
log() {
  # Protection with ${1:-} and ${2:-} ensures that set -u does not fail if an argument
  # is omitted in the function call.
  local LEVEL="${1:-}" 
  local MESSAGE="${2:-}"
  local CONTEXT=""

  [[ -n "$CLIENT_NAME" ]] && CONTEXT+="Client:$CLIENT_NAME "
  [[ -n "$CLOUD_PROVIDER" ]] && CONTEXT+="Cloud:$CLOUD_PROVIDER "
  [[ -n "$ACCOUNT_ID" && "$ACCOUNT_ID" != "undefined" ]] && CONTEXT+="Account:$ACCOUNT_ID "

  local TS
  TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  # Log line now secure against unbound variable errors
  echo "[RUNNER:$SESSION_ID] $TS [$LEVEL] ${CONTEXT}${MESSAGE}"
}

# ============================================================
# 🔧 AWS Utilities
# ============================================================

aws_cli() { aws --region "$AWS_REGION" "$@"; }

get_ssm_value() {
  local path="$1"
  # Protection: ${path:-} ensures that the script does not fail if get_ssm_value is called without an argument
  aws_cli ssm get-parameter --with-decryption --name "${path:-}" \
    --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

# ============================================================
# 🔐 MultiCloud Authentication
# ============================================================

authenticate() {
  case "$CLOUD_PROVIDER" in
    aws)
      log "INFO" "☁️ Starting AWS authentication (automatic token regeneration mode)..."

      ROLE_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/role"
      ROLE_ARN="$(get_ssm_value "$ROLE_PATH")"

      if [[ -z "$ROLE_ARN" ]]; then
        log "ERROR" "❌ No Role ARN found in $ROLE_PATH. Aborting execution."
        return 1
      fi

      log "INFO" "🔑 Generating new temporary credentials via STS assume-role..."
      CREDS_JSON="$(aws sts assume-role \
        --role-arn "$ROLE_ARN" \
        --role-session-name "MulticloudAssessment-${SESSION_ID}" \
        --duration-seconds 3600)"

      export AWS_ACCESS_KEY_ID="$(echo "$CREDS_JSON" | jq -r '.Credentials.AccessKeyId')"
      export AWS_SECRET_ACCESS_KEY="$(echo "$CREDS_JSON" | jq -r '.Credentials.SecretAccessKey')"
      export AWS_SESSION_TOKEN="$(echo "$CREDS_JSON" | jq -r '.Credentials.SessionToken')"
      export AWS_DEFAULT_REGION="$AWS_REGION"

      UPDATED_CREDS_JSON=$(jq -n \
        --arg id "$AWS_ACCESS_KEY_ID" \
        --arg secret "$AWS_SECRET_ACCESS_KEY" \
        --arg token "$AWS_SESSION_TOKEN" \
        '{AWS_ACCESS_KEY_ID:$id, AWS_SECRET_ACCESS_KEY:$secret, AWS_SESSION_TOKEN:$token}')

      if aws ssm put-parameter \
          --name "/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/access" \
          --value "$UPDATED_CREDS_JSON" \
          --type "SecureString" \
          --overwrite >/dev/null 2>&1; then
        log "INFO" "💾 New STS token successfully written to SSM (overwrite performed)."
      else
        log "WARN" "⚠️ Failed to refresh STS token in SSM (check permissions)."
      fi

      log "INFO" "✅ AWS authentication completed. Running Agentic Cloud Assessment..."
      prowler aws \
        ---output-formats csv html json-asff \
        --compliance aws_well_architected_framework_reliability_pillar_aws aws_well_architected_framework_security_pillar_aws iso27001_2022_aws mitre_attack_aws nist_800_53_revision_5_aws prowler_threatscore_aws soc2_aws \
        --output-filename "agentic-mcsp-aws-${ACCOUNT_ID}.json" \
        --output-directory "$OUTPUT_DIR" \
        --no-banner \
        --log-level "$LOG_LEVEL" || log "WARN" "⚠️ Partial failure in AWS scan"
      ;;


    azure)
      log "INFO" "☁️ Starting Azure Authentication..."
      CREDS_PATH="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials/access"
      CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"
      [[ -z "$CREDS_RAW" ]] && { log "ERROR" "❌ Azure credentials not found at $CREDS_PATH"; return 1; }

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

      log "INFO" "▶️ Executando Agentic Cloud Assessment Azure..."
      prowler azure \
        --sp-env-auth \
        --output-formats csv html json-asff \
        --compliance cis_4.0_azure iso27001_2022_azure  mitre_attack_azure prowler_threatscore_azure soc2_azure \
        --output-filename "agentic-mcsp-azure-${ACCOUNT_ID}.json" \
        --output-directory "$OUTPUT_DIR" \
        --no-banner \
        --log-level "$LOG_LEVEL" || log "WARN" "⚠️ Partial failure in Azure scan"
      ;;

    gcp)
      log "INFO" "🌍 Starting GCP authentication..."
      CREDS_PATH_BASE="/clients/$CLIENT_NAME/gcp"

      FILTERED_PARAM=$(aws_cli ssm describe-parameters \
        --parameter-filters "Key=Name,Option=BeginsWith,Values=$CREDS_PATH_BASE/$ACCOUNT_ID/" \
        --query "Parameters[?contains(Name, '/credentials/access')].Name" \
        --output text | tr '\t' '\n' | head -n 1)

      [[ -z "$FILTERED_PARAM" ]] && { log "ERROR" "❌ No parameters found in SSM for $ACCOUNT_ID."; return 1; }

      CREDS_RAW="$(aws_cli ssm get-parameter --with-decryption --name "$FILTERED_PARAM" \
        --query "Parameter.Value" --output text 2>/dev/null || true)"
      [[ -z "$CREDS_RAW" ]] && { log "ERROR" "❌ GCP credentials not found in $FILTERED_PARAM"; return 1; }

      CLEAN_JSON="$(echo "$CREDS_RAW" | jq -r 'fromjson? // .')"
      TMP_KEY="/tmp/gcp-${ACCOUNT_ID}.json"
      echo "$CLEAN_JSON" > "$TMP_KEY"
      export GOOGLE_APPLICATION_CREDENTIALS="$TMP_KEY"

      if gcloud auth activate-service-account --key-file="$TMP_KEY" --quiet; then
        gcloud config set project "$ACCOUNT_ID" --quiet
        log "INFO" "✅ GCP authentication completed."
      else
        log "ERROR" "❌ GCP authentication failed."
        return 1
      fi

      log "INFO" "▶️ Running Agentic Cloud Assessment GCP..."
      prowler gcp \
        --project-id "$ACCOUNT_ID" \
        --output-formats csv html json-asff \
        --compliance cis_4.0_gcp iso27001_2022_gcp  mitre_attack_gcp prowler_threatscore_gcp soc2_gcp \
        --output-filename "agentic-mcsp-gcp-${ACCOUNT_ID}.json" \
        --output-directory "$OUTPUT_DIR" \
        --skip-api-check \
        --no-banner \
        --log-level "$LOG_LEVEL" || log "WARN" "⚠️ Partial failure in GCP scan"
      rm -f "$TMP_KEY" || true
      ;;
  esac
}

# ============================================================
# 🚀 Main execution 
# ============================================================

if ! authenticate; then
  log "ERROR" "⚠️ Authentication failed. Terminating execution."
  exit 1
fi

# Automatic upload to S3
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
S3_PATH="s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}/"

# === Ensures use of the global AWS CLI (not Poetry) ===
export PATH=/usr/local/bin:/usr/bin:/bin

# === Restores original ECS credentials (source) ===
log "INFO" "♻️ Reverting credentials to source account (ECS Task Role) for upload to S3..."
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

# Optional Diagnostics — Displays which account is active now
aws sts get-caller-identity --output text | awk '{print "🆔 Active account for upload:", $3}' || true

# Perform upload with bucket ownership control
echo "Upload artifacts on the path $S3_PATH" # Fixed from $PATH to $S3_PATH
cd /
if aws s3 cp "$OUTPUT_DIR/" "$S3_PATH" \
    --recursive \
    --only-show-errors \
    --acl bucket-owner-full-control ; then
  log "INFO" "☁️ Reports successfully sent to $S3_PATH"
else
  log "WARN" "⚠️ Upload to S3 failed (check permissions)."
fi


END_TS=$(date +%s)
DURATION=$((END_TS - START_TS))
log "INFO" "⏱️ Execution completed on ${DURATION}s."

log "========== 🔍 EXECUTION SUMMARY =========="
log "INFO" "Session ID: $SESSION_ID"
log "INFO" "Created At: $CREATED_AT"
log "INFO" "Client:     $CLIENT_NAME"
log "INFO" "Cloud:      $CLOUD_PROVIDER"
log "INFO" "Account:    $ACCOUNT_ID"
log "INFO" "Region:     $AWS_REGION"
log "INFO" "Output:     $OUTPUT_DIR"
log "INFO" "S3 Path:    $S3_PATH"
log "=========================================="
