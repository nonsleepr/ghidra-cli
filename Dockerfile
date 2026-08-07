# syntax=docker/dockerfile:1

# --- Stage 1: build the ghidra-cli binary -----------------------------------
FROM rust:1-bookworm AS builder

WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock build.rs ./
COPY docs ./docs
RUN mkdir -p src/bin .claude/skills/ghidra-cli \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && touch .claude/skills/ghidra-cli/SKILL.fallback.md \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --locked --bin ghidra-cli

# --- Stage 2: runtime image with Ghidra + JDK --------------------------------
# Debian bookworm's own repos only go up to OpenJDK 17, so a JDK 21 runtime
# means either bookworm-backports or a distro that ships it. Temurin's own
# image sidesteps the question entirely and matches the JDK this project's CI
# already tests against (actions/setup-java, distribution: temurin).
FROM eclipse-temurin:21-jdk-jammy AS runtime

ARG GHIDRA_VERSION=

# `analyzeHeadless` passes -Djava.awt.headless=true, but Ghidra's own startup
# path still ends up loading the full X11 AWT toolkit (libawt_xawt.so, not
# libawt_headless.so) rather than a true headless one, so libXext/libXtst/
# libXrender/libXi are required even though nothing is ever rendered. This is
# a long-standing Ghidra-specific footgun (reported as far back as Ghidra
# 9.0.4: https://github.com/blacktop/docker-ghidra/issues/3), not a generic
# "any headless JVM needs X11" myth — see README Troubleshooting > "Missing
# X11 Libraries" for the same footgun on bare-metal Linux/WSL installs.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libxtst6 \
    libxext6 \
    libxrender1 \
    libxi6 \
    fontconfig \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/ghidra-cli /usr/local/bin/ghidra-cli

# Bake the latest (or pinned, via --build-arg GHIDRA_VERSION) Ghidra release
# into the image using the CLI's own installer, so the image doesn't depend on
# any third-party Ghidra distribution. Optionally pass a token to avoid
# GitHub's 60 req/hour unauthenticated API limit:
#   docker build --secret id=github_token,env=GITHUB_TOKEN .
RUN --mount=type=secret,id=github_token \
    if [ -s /run/secrets/github_token ]; then export GITHUB_TOKEN="$(cat /run/secrets/github_token)"; fi \
    && ghidra-cli setup --dir /opt/ghidra ${GHIDRA_VERSION:+--version "$GHIDRA_VERSION"} \
    && ln -s "$(find /opt/ghidra -maxdepth 1 -name 'ghidra_*' -type d)" /opt/ghidra/current

ENV GHIDRA_INSTALL_DIR=/opt/ghidra/current
# Ghidra 12 rejects path components starting with '.' (e.g. the default
# ~/.cache-based project dir), so point at a plain mount path instead.
ENV GHIDRA_PROJECT_DIR=/projects

RUN mkdir -p /projects /binaries

VOLUME ["/projects"]
WORKDIR /work

ENTRYPOINT ["ghidra-cli"]
CMD ["--help"]
