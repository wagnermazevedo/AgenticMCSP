#!/usr/bin/env bash
# ============================================================
# Agentic Multi Cloud Security Assessment Runner - v4.2.4
# Author: Wagner Azevedo
# Changes:
# - Added "help" mode to display compatible syntax per provider
# - Retains safe env/arg precedence logic
# - Prefix multicloudassessment-* for outputs
# - DRY_RUN=true support
# - Robust GCP credential normalization
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION_REV="v4.2.4"

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Starting Agentic Multicloud Runner ${VERSION_REV}"

# -----------------------------
# Safe environment pick logic
# -----------------------------
_safe_pick() {
  local envname="$1"; local posval="${2:-}"; local defval="${3:-}"
  local envval="${!envname:-}"
  if [[ -n "${envval}" ]]; then echo "${envval}"
  elif [[ -n "${posval}" ]]; then echo "${posval}"
  else echo "${defval}"; fi
}

ARG1="${1:-}"
ARG2="${2:-}"
ARG3="${3:-}"

CLIENT_NAME=$(_safe_pick "CLIENT_NAME" "${ARG1}" "unknown")
CLOUD_PROVIDER=$(_safe_pick "CLOUD_PROVIDER" "${ARG2}" "unknown")
ACCOUNT_ID=$(_safe_pick "ACCOUNT_ID" "${ARG3}" "undefined")

AWS_REGION="${AWS_REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-agentic-mcsp-assessments}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
DRY_RUN="${DRY_RUN:-false}"

OUTPUT_DIR="/tmp/output-${SESSION_ID}"
mkdir -p "$OUTPUT_DIR"

log() {
  local LEVEL="${1:-INFO}"; shift || true
  local MESSAGE="$*"
  local TS; TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "[RUNNER:${SESSION_ID}] ${TS} [${LEVEL}] Client:${CLIENT_NAME} Cloud:${CLOUD_PROVIDER} Account:${ACCOUNT_ID} ${MESSAGE}"
}

aws_cli() { aws --region "${AWS_REGION}" "$@"; }

get_ssm_value() {
  local path="$1"
  aws_cli ssm get-parameter --with-decryption --name "${path}" \
    --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

# -----------------------------------------
# Detect compatible output syntax
# -----------------------------------------
detect_output_flag() {
  local provider="$1"
  local HELP_OUTPUT
  HELP_OUTPUT="$(prowler ${provider} -h 2>&1 || true)"
  if echo "$HELP_OUTPUT" | grep -q '\-M'; then
    echo "-M csv,html,json-asff"
  elif echo "$HELP_OUTPUT" | grep -q 'output-formats'; then
    echo "--output-formats csv html json-asff"
  else
    echo ""
  fi
}

# -----------------------------------------
# "help" mode: show syntax per provider
# -----------------------------------------
if [[ "${1:-}" == "help" ]]; then
  TARGET="${2:-aws}"
  log "INFO" "🧩 Detecting compatible syntax for '${TARGET}'..."
  FLAG=$(detect_output_flag "$TARGET")
  echo ""
  echo "👉 Compatible syntax for '${TARGET}':"
  echo "-----------------------------------------"
  echo "prowler ${TARGET} ${FLAG} --compliance <frameworks> --output-filename <file> --output-directory <path>"
  echo "-----------------------------------------"
  echo "Supported frameworks (for ${TARGET}):"
  case "$TARGET" in
    aws)
      echo "aws_well_architected_framework_reliability_pillar_aws"
      echo "aws_well_architected_framework_security_pillar_aws"
      echo "iso27001_2022_aws"
      echo "mitre_attack_aws"
      echo "nist_800_53_revision_5_aws"
      echo "prowler_threatscore_aws"
      echo "soc2_aws"
      ;;
    azure)
      echo "cis_4.0_azure"
      echo "iso27001_2022_azure"
      echo "mitre_attack_azure"
      echo "prowler_threatscore_azure"
      echo "soc2_azure"
      ;;
    gcp)
      echo "cis_4.0_gcp"
      echo "iso27001_2022_gcp"
      echo "mitre_attack_gcp"
      echo "prowler_threatscore_gcp"
      echo "soc2_gcp"
      ;;
  esac
  echo ""
  exit 0
fi

# -----------------------------------------
# Robust GCP credential normalization
# -----------------------------------------
normalize_gcp_creds() {
  local raw="$1"
  local clean=""
  if echo "$raw" | grep -q '^{\\\"'; then
    clean="$(echo "$raw" | sed 's/^"//' | sed 's/"$//' | jq -r 'fromjson')"
  elif echo "$raw" | grep -q '{\"'; then
    clean="$(echo "$raw" | jq -r 'fromjson? // .')"
  else
    if echo "$raw" | jq empty >/dev/null 2>&1; then
      clean="$raw"
    else
      if echo "$raw" | base64 --decode >/dev/null 2>&1; then
        clean="$(echo "$raw" | base64 --decode)"
      else
        clean="$raw"
      fi
    fi
  fi
  if ! echo "$clean" | jq empty >/dev/null 2>&1; then
    return 1
  fi
  printf "%s" "$clean"
}

# -----------------------------------------
# Prowler wrapper with fallback
# -----------------------------------------
run_prowler_safe() {
  local provider="$1"
  local filename_base="$2"
  local extras="$3"

  local OUTFLAG; OUTFLAG="$(detect_output_flag "$provider")"
  local CMD="prowler ${provider} ${OUTFLAG} ${extras} \
    --output-filename ${filename_base} \
    --output-directory ${OUTPUT_DIR} \
    --no-banner \
    --log-level ${LOG_LEVEL}"

  log "INFO" "▶️ Command: ${CMD}"
  if [[ "${DRY_RUN,,}" == "true" ]]; then
    echo ""
    echo "🔎 DRY_RUN enabled. Would execute:"
    echo "${CMD}"
    echo ""
    exit 0
  fi

  if ! eval "${CMD}"; then
    log "WARN" "⚠️ Primary syntax failed, trying fallback..."
    eval "prowler ${provider} -M csv,html,json-asff ${extras} \
      --output-filename ${filename_base} --output-directory ${OUTPUT_DIR} \
      --no-banner --log-level ${LOG_LEVEL}" || log "WARN" "⚠️ Fallback also failed."
  fi
}

# ============================================================
# 🔐 Authentication + Scan
# ============================================================
authenticate_and_scan() {
  case "${CLOUD_PROVIDER}" in
    aws)
      log "INFO" "☁️ Authenticating to AWS..."
      ROLE_PATH="/clients/${CLIENT_NAME}/aws/${ACCOUNT_ID}/role"
      ROLE_ARN="$(get_ssm_value "${ROLE_PATH}")"
      [[ -z "${ROLE_ARN}" ]] && { log "ERROR" "❌ Missing Role ARN at ${ROLE_PATH}"; return 1; }
      CREDS_JSON="$(aws sts assume-role --role-arn "${ROLE_ARN}" --role-session-name "AgenticMCSP-${SESSION_ID}" --duration-seconds 3600)"
      export AWS_ACCESS_KEY_ID="$(echo "$CREDS_JSON" | jq -r '.Credentials.AccessKeyId')"
      export AWS_SECRET_ACCESS_KEY="$(echo "$CREDS_JSON" | jq -r '.Credentials.SecretAccessKey')"
      export AWS_SESSION_TOKEN="$(echo "$CREDS_JSON" | jq -r '.Credentials.SessionToken')"
      run_prowler_safe "aws" "multicloudassessment-aws-${ACCOUNT_ID}" \
        "--compliance aws_well_architected_framework_reliability_pillar_aws \
         aws_well_architected_framework_security_pillar_aws \
         iso27001_2022_aws mitre_attack_aws nist_800_53_revision_5_aws \
         prowler_threatscore_aws soc2_aws"
      ;;

    azure)
      log "INFO" "☁️ Authenticating to Azure..."
      CREDS_PATH="/clients/${CLIENT_NAME}/azure/${ACCOUNT_ID}/credentials/access"
      CREDS_RAW="$(get_ssm_value "${CREDS_PATH}")"
      CLEAN_JSON="$(echo "${CREDS_RAW}" | jq -r 'fromjson? // .')"
      export AZURE_TENANT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_TENANT_ID')"
      export AZURE_CLIENT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_ID')"
      export AZURE_CLIENT_SECRET="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_SECRET')"
      export AZURE_SUBSCRIPTION_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_SUBSCRIPTION_ID')"
      az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1
      run_prowler_safe "azure" "multicloudassessment-azure-${ACCOUNT_ID}" \
        "--sp-env-auth --compliance cis_4.0_azure iso27001_2022_azure mitre_attack_azure prowler_threatscore_azure soc2_azure"
      ;;

    gcp)
      log "INFO" "🌍 Authenticating to GCP..."
      CREDS_PATH="/clients/${CLIENT_NAME}/gcp/${ACCOUNT_ID}/credentials/access"
      RAW="$(get_ssm_value "${CREDS_PATH}")"
      CLEAN="$(normalize_gcp_creds "${RAW}")"
      TMP_KEY="/tmp/gcp-${ACCOUNT_ID}.json"
      printf "%s" "${CLEAN}" > "${TMP_KEY}"
      export GOOGLE_APPLICATION_CREDENTIALS="${TMP_KEY}"
      gcloud auth activate-service-account --key-file="${TMP_KEY}" --quiet
      gcloud config set project "${ACCOUNT_ID}" --quiet
      run_prowler_safe "gcp" "multicloudassessment-gcp-${ACCOUNT_ID}" \
        "--project-id ${ACCOUNT_ID} --skip-api-check \
         --compliance cis_4.0_gcp iso27001_2022_gcp mitre_attack_gcp prowler_threatscore_gcp soc2_gcp"
      rm -f "${TMP_KEY}" || true
      ;;
  esac
}

# ============================================================
# 🚀 Main
# ============================================================
if ! authenticate_and_scan; then
  log "ERROR" "⚠️ Authentication or scan failed. Aborting."
  exit 1
fi

TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
S3_PATH="s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}/"
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN || true

log "INFO" "☁️ Uploading reports to ${S3_PATH}"
if aws s3 cp "${OUTPUT_DIR}/" "${S3_PATH}" --recursive --only-show-errors --acl bucket-owner-full-control; then
  log "INFO" "✅ Reports uploaded successfully."
else
  log "WARN" "⚠️ Upload failed (check role or bucket policy)."
fi
