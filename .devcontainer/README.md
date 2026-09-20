# Public development container

Open this repository with a Dev Containers client, or build on an authorized container builder:

```sh
docker build --file .devcontainer/Dockerfile --tag buaa-cli-dev:local .devcontainer
```

The build requires public Docker Hub, Rust component and GitHub release downloads, but no credentials and no campus access. The workspace is mounted only at runtime; the build context is allowlisted to the Dockerfile and ignore file. The only `COPY` instructions copy Node files from the pinned official image stage. There is no private operational recipe, HOME, model configuration, GitHub hosts file, SSH key, service credential or Life checkout in the image or public source.

## Pinned inputs

- Official `rust:1.98.1-bookworm` image index: `sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e`.
- Official `node:22.23.2-bookworm-slim` image index: `sha256:48e4b67d85f87bd551df43704e24d252f56cc5f8e9718841aace50f19948f0f9`.
- OMP [v18.2.6 standalone release](https://github.com/can1357/oh-my-pi/releases/tag/v18.2.6), verified against its [SHA256SUMS.txt](https://github.com/can1357/oh-my-pi/releases/download/v18.2.6/SHA256SUMS.txt):
  - Linux amd64: `0f38598c91e823d8cce07f151ec3999d51f213fb2cc3e07d89f1af8eef9247a2`.
  - Linux arm64: `07245cbe050c3999ab5cea9babfe84e7e8819d2f4d5e49bef47c0aacb6b957e4`.
- OMP license/notices downloads also have literal checksum checks. Unsupported architectures fail rather than selecting an unpinned fallback.

Both official image index byte hashes were verified against the registry's `Docker-Content-Digest`, not just mutable tags. Rustfmt/clippy are installed for exact Rust 1.98.1; rustup verifies the release manifest's component hashes. No moving apt repository, npm package, Dev Container feature or editor extension is installed. These pins stabilize software inputs; the resulting image is not claimed byte-for-byte reproducible across builders/timestamps.

## Private state and account identity

The image runs unprivileged as `vscode`. A fixed Docker volume, `buaa-cli-governed-home`, retains the private HOME across rebuilds and is deliberately **not** named per worktree. A newly created volume contains no owner credentials. This volume is local private runtime state, never a build input or published image layer. Do not delete it to clear a governor latch or cooldown.

Every process using one campus account must use one governed identity/state domain. Do not run this profile against an account concurrently with another container/user/host using a separate HOME. The private operational devcontainer may have a different identity: coordinate its shared governor storage before enabling any real adapter. The current verified CLI features are offline-only. This recipe does not grant campus read/write or authentication permission.

No host HOME, SSH socket, Docker socket or model/service secret is explicitly mounted by this definition. A client may implement its own Git/SSH credential forwarding; disable that client behavior for credential-free work. Configure any future authorized model/account access only in private runtime state, never in this Dockerfile, build arguments, environment committed to Git or public fixtures.

## Verification boundary

The existing devcontainer's OMP executable reports `omp/18.2.6` and matches the published amd64 SHA-256; Node reports `v22.23.2`. This verifies the release pin, not the new Docker image. Docker/Podman and a builder socket are unavailable in the current development seat, so a full image build has not been run here. The recipe includes fail-fast checksum/version checks. Source/CI work remains in this devcontainer; do not move compilation to the PVE host to bypass that limitation.

After an authorized image build, run inside the new container:

```sh
cargo fetch --locked
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
```

The first command downloads public crates only. Tests must remain synthetic/offline with respect to campus. No private CI bridge is activated by this definition.
