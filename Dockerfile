# ============================================================
# MultiCloud Assessment Runner - FIXED
# Base: Official Prowler image (override old Poetry virtualenv)
# ============================================================
FROM public.ecr.aws/prowler-cloud/prowler:latest
LABEL maintainer="Wagner Azevedo"
LABEL description="MultiCloud Assessment Platform Runner (AWS, Azure, GCP, M365)"

USER root

# === Dependências básicas ===
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        git jq curl unzip bash wget ca-certificates gnupg lsb-release \
        apt-transport-https dos2unix uuid-runtime awscli && \
    rm -rf /var/lib/apt/lists/*

# === Corrige PATH e remove virtualenv antigo ===
RUN rm -rf /home/prowler/.cache/pypoetry || true
ENV PATH="/usr/local/bin:/usr/bin:/bin"

# === Instala versão atual do Prowler ===
RUN git clone --depth 1 https://github.com/prowler-cloud/prowler.git /opt/prowler && \
    cd /opt/prowler && pip install -r requirements.txt && \
    ln -sf /opt/prowler/prowler /usr/local/bin/prowler

# === Copia scripts ===
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY run-prowler.sh /usr/local/bin/run-prowler.sh
COPY run-multicloudassessment.sh /usr/local/bin/run-multicloudassessment.sh
COPY run-multicloud-wrapper.sh /usr/local/bin/run-multicloud-wrapper.sh

# === Ajusta permissões e encoding ===
RUN dos2unix /usr/local/bin/*.sh && chmod +x /usr/local/bin/*.sh

WORKDIR /home/prowler
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
