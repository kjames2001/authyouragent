# The Auth Your Agent MCP server (stdio). The browser vault is a separate image:
# ghcr.io/kjames2001/authyouragent-vault, started with `authyouragent vault up`.
#
#   docker build -t authyouragent-mcp .
#   docker run -i --rm authyouragent-mcp
#
# Pass the settings printed by `authyouragent vault env` with -e, and mount the
# agent's key file read-only. Without settings the server still starts and
# lists its tools; each tool then says what is missing.
FROM python:3.12-slim
RUN useradd -m -u 10001 mcp
COPY sdk /src/sdk
RUN pip install --no-cache-dir "/src/sdk[mcp]" && rm -rf /src
USER mcp
ENTRYPOINT ["authyouragent-mcp"]
