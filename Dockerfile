# ENVY Recon in a container: the command-line OSINT terminal, nothing else.
#   docker run --rm -it ghcr.io/xzchick/envy-recon                 # interactive terminal
#   docker run --rm ghcr.io/xzchick/envy-recon domain example.com  # one lookup
#   docker run --rm -v "$PWD:/work" ghcr.io/xzchick/envy-recon meta photo.jpg --offline

FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY envy_recon ./envy_recon
RUN pip install --no-cache-dir build \
 && python -m build --wheel --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.title="ENVY Recon" \
      org.opencontainers.image.description="OSINT terminal for domains, IPs, certificates and file metadata. Prints every network request; --offline blocks them all." \
      org.opencontainers.image.source="https://github.com/xzchick/envy-recon" \
      org.opencontainers.image.url="https://xzchick.github.io/homebrew-envy/recon/" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl \
 && rm -f /tmp/*.whl \
 && useradd --create-home --uid 10001 recon
USER recon
WORKDIR /work
ENTRYPOINT ["envy-recon"]
