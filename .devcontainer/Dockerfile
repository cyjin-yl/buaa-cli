# Public build inputs only. No local COPY/ADD, private HOME, or build secrets.
# Image-index digests verified against registry-1.docker.io on 2026-09-20.
FROM docker.io/library/node:22.23.2-bookworm-slim@sha256:48e4b67d85f87bd551df43704e24d252f56cc5f8e9718841aace50f19948f0f9 AS node
FROM docker.io/library/rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e

# The pinned Rust buildpack-deps base already supplies git, curl, Python 3 and
# native build tools. No moving apt repository is consulted by this recipe.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/ /usr/local/lib/node_modules/

RUN set -eu; \
    ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm; \
    ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx; \
    rustup component add --toolchain 1.98.1 rustfmt clippy; \
    test "$(node --version)" = v22.23.2; \
    python3 --version; \
    git --version; \
    groupadd --gid 1000 vscode; \
    useradd --uid 1000 --gid vscode --create-home --shell /bin/bash vscode; \
    chmod 0700 /home/vscode; \
    install -d -m 0700 -o vscode -g vscode /home/vscode/.cargo; \
    install -d -m 0755 -o vscode -g vscode /workspace; \
    chmod -R go-w /usr/local/rustup /usr/local/cargo

# OMP is the official standalone release, not an npm/latest install script.
# Hashes are from v18.2.6/SHA256SUMS.txt and the release asset metadata.
# Only the two explicitly checksum-pinned glibc architectures are supported.
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) asset=omp-linux-x64; digest=0f38598c91e823d8cce07f151ec3999d51f213fb2cc3e07d89f1af8eef9247a2 ;; \
      arm64) asset=omp-linux-arm64; digest=07245cbe050c3999ab5cea9babfe84e7e8819d2f4d5e49bef47c0aacb6b957e4 ;; \
      *) printf '%s\n' 'Unsupported architecture: OMP image supports amd64 and arm64 only' >&2; exit 1 ;; \
    esac; \
    release=https://github.com/can1357/oh-my-pi/releases/download/v18.2.6; \
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location "$release/$asset" --output /tmp/omp; \
    printf '%s  /tmp/omp\n' "$digest" | sha256sum --check --strict -; \
    install -m 0755 /tmp/omp /usr/local/bin/omp; \
    rm /tmp/omp; \
    install -d /usr/local/share/doc/omp; \
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location "$release/LICENSE" --output /usr/local/share/doc/omp/LICENSE; \
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location "$release/THIRD-PARTY-NOTICES.txt" --output /usr/local/share/doc/omp/THIRD-PARTY-NOTICES.txt; \
    printf '%s\n' \
      '16c45f9d667442781f03fa198914cc39abcaa48ec5ed8f644643e554ca2fbf63  /usr/local/share/doc/omp/LICENSE' \
      '73c0c20e5b9b3ecedb5d6dbfcdd73905155927f52ae8a4d1d04fedcfacf0626e  /usr/local/share/doc/omp/THIRD-PARTY-NOTICES.txt' \
      | sha256sum --check --strict -

ENV HOME=/home/vscode \
    CARGO_HOME=/home/vscode/.cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
USER vscode
WORKDIR /workspace
RUN test "$(omp --version)" = omp/18.2.6 && cargo --version && npm --version
CMD ["sleep", "infinity"]
