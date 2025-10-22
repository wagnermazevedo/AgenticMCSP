# ============================================================
# MultiCloud Assessment Runner - FINAL FIX (Prowler 5.x)
# ============================================================
FROM public.ecr.aws/prowler-cloud/prowler:latest
LABEL maintainer="Wagner Azevedo"
LABEL description="MultiCloud Assessment Platform Runner (AWS, Azure, GCP, M365)"

USER root

# === Dependências básicas ===
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        git jq curl unzip bash wget ca-certificates gnupg lsb-release \
        apt-transport-https dos2unix uuid-runtime python3-pip && \
    rm -rf /var/lib/apt/lists/*

# === Corrige PATH e remove virtualenv antigo ===
RUN rm -rf /home/prowler/.cache/pypoetry || true
ENV PATH="/usr/local/bin:/usr/bin:/bin"

# === Atualiza para a versão mais recente do Prowler ===
RUN pip install --no-cache-dir --upgrade prowler-cloud && \
    echo "[INFO] ✅ Installed Prowler version: $(prowler --version 2>&1)"

# === Copia scripts ===
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY run-prowler.sh /usr/local/bin/run-prowler.sh
COPY run-multicloudassessment.sh /usr/local/bin/run-multicloudassessment.sh
COPY run-multicloud-wrapper.sh /usr/local/bin/run-multicloud-wrapper.sh

# === Ajusta permissões e encoding ===
RUN dos2unix /usr/local/bin/*.sh && chmod +x /usr/local/bin/*.sh

WORKDIR /home/prowler
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
