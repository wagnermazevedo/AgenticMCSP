#!/usr/bin/env bash
set -euo pipefail

echo "[ENTRYPOINT] 🔹 Starting container in $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# ==============================
# Detect Cloud Provider and required variables 
# ==============================
required_vars=("CLIENT_NAME" "CLOUD_PROVIDER" "ACCOUNT_ID")
for var in "${required_vars[@]}"; do
  if [ -z "${!var:-}" ]; then
    echo "[ENTRYPOINT] ❌ Required value  '${var}' not defined. Aborting."
    exit 1
  fi
done

CLOUD_PROVIDER=$(echo "$CLOUD_PROVIDER" | tr '[:upper:]' '[:lower:]')

echo "[ENTRYPOINT] 🌐 Environment values received:"
echo "  CLIENT_NAME=$CLIENT_NAME"
echo "  CLOUD_PROVIDER=$CLOUD_PROVIDER"
echo "  ACCOUNT_ID=$ACCOUNT_ID"
echo "  S3_BUCKET=${S3_BUCKET:-multicloud-assessments}"

# ==============================
# Funções utilitárias
# ==============================

install_base_deps() {
  echo "[ENTRYPOINT] ⚙️ Installing dependencies..."
  apt-get update -y && \
  apt-get install -y --no-install-recommends jq curl unzip bash wget ca-certificates gnupg lsb-release apt-transport-https dos2unix uuid-runtime && \
  rm -rf /var/lib/apt/lists/*
}

install_aws_cli() {
  if ! command -v aws &>/dev/null; then
    echo "[ENTRYPOINT] 📦 Installing AWS CLI (SSM backend requirement)..."
    curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip && ./aws/install && rm -rf awscliv2.zip ./aws
    if command -v aws &>/dev/null; then
      echo "[ENTRYPOINT] ✅ AWS CLI installed sucessfully: $(aws --version 2>&1)"
    else
      echo "[ENTRYPOINT] ❌ Failed to install AWS CLI. Aborting."
      exit 1
    fi
  else
    echo "[ENTRYPOINT] ✅ AWS CLI already installed: $(aws --version 2>&1)"
  fi
}

install_azure_cli() {
  if ! command -v az &>/dev/null; then
    echo "[ENTRYPOINT] 📦 Installing Azure CLI..."
    curl -sL https://aka.ms/InstallAzureCLIDeb | bash
  else
    echo "[ENTRYPOINT] ✅ Azure CLI already installed: $(az version 2>/dev/null | head -n 1 || echo 'detected')"
  fi
}

install_gcloud() {
  if ! command -v gcloud &>/dev/null; then
    echo "[ENTRYPOINT] 📦 Installing Google Cloud SDK..."
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
      > /etc/apt/sources.list.d/google-cloud-sdk.list
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
    apt-get update -y && apt-get install -y --no-install-recommends google-cloud-cli && rm -rf /var/lib/apt/lists/*
    echo "[ENTRYPOINT] ✅ Google Cloud SDK installed: $(gcloud version | head -n 1)"
  else
    echo "[ENTRYPOINT] ✅ Google Cloud SDK alreaddy installed: $(gcloud version | head -n 1)"
  fi
}

configure_virtualenv_path() {
  local VENV_PATH
  VENV_PATH=$(find /home/prowler/.cache/pypoetry/virtualenvs -type d -name "prowler-*-py3.*" | head -n 1 || true)
  if [ -n "$VENV_PATH" ]; then
    export PATH="$VENV_PATH/bin:$PATH"
    echo "[ENTRYPOINT] 🧠 Virtual environment detected: $VENV_PATH"
  else
    echo "[ENTRYPOINT] ⚠️ Virtualenv environment not detected, using standard PATH."
  fi
}

# ==============================
# Main function
# ==============================
main() {
  install_base_deps
  install_aws_cli   # AWS CLI is required for all cloud provider (SSM backend)

  # Specific dependencies for cloud provider (beyond AWS CLI)
  case "$CLOUD_PROVIDER" in
    aws)
      echo "[ENTRYPOINT] 🌩️ AWS environment selected —AWS CLI required only."
      ;;
    azure)
      install_azure_cli
      ;;
    gcp)
      install_gcloud
      ;;
    *)
      echo "[ENTRYPOINT] ❌ Cloud Service Provider invalid: $CLOUD_PROVIDER"
      exit 1
      ;;
  esac

  configure_virtualenv_path

  echo "[ENTRYPOINT] ✅ Environment prepared. Performing wrapper and runner..."
  if [ -x /usr/local/bin/run-multicloudassessment.sh ]; then
    chmod +x /usr/local/bin/run-multicloudassessment.sh
    exec /usr/local/bin/run-multicloud-wrapper.sh "$CLIENT_NAME" "$CLOUD_PROVIDER" "$ACCOUNT_ID" || {
      echo "[ENTRYPOINT] ❌ Failed to perform runner."
      exit 1
    }
  else
    echo "[ENTRYPOINT] ❌ Runner script not found in /usr/local/bin/run-multicloudassessment.sh"
    ls -la /usr/local/bin
    exit 1
  fi

  echo "[ENTRYPOINT] 🏁 Performed sucessfully in em $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}

main "$@"
