# H2: pinned by digest — tag python:3.12.11-slim is mutable; digest is not
FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f

WORKDIR /app

# Layer order optimisé pour le cache Docker :
# packages/ change rarement (deps) → invalidation minimale sur les builds courants
COPY packages/ /app/packages/
COPY setup.py /app/
# src/ change à chaque commit → placé après les deps pour ne pas invalider le layer packages
COPY src/ /app/src/
# Métadonnées et docs : pas nécessaires avant l'install
COPY README.md LICENSE /app/

# Install dependencies
RUN pip install --no-cache-dir .

# M1: create non-root user first, then set directories with least-privilege permissions
RUN adduser --disabled-password --gecos "" fractumuser \
    && mkdir -p /data /app/shares \
    && chown -R fractumuser:fractumuser /app /data /app/shares \
    && chmod 750 /data /app/shares

USER fractumuser

VOLUME ["/data", "/app/shares"]

ENTRYPOINT ["fractum"]
CMD ["--help"]
