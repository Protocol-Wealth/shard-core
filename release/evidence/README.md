# Sanitized offline-build evidence

Release evidence may be kept in a pull-request discussion or a controlled
register. It must contain only non-secret build and verification facts.

Record:

- UTC start and completion times
- source commit and Git tree
- smoke-evidence file SHA-256
- bundle directory name and `SHA256SUMS` SHA-256
- project wheel filename and SHA-256
- runtime and build lock SHA-256 values
- canonical runtime and build wheelhouse inventory SHA-256 values
- Git, Python, Podman, crun, and conmon executable SHA-256 values
- Podman configuration-tree SHA-256
- image index, platform-manifest, and image-config digests
- operating-system, WSL, kernel, cgroup, storage-driver, and user-session facts
- installer, `pip check`, import smoke, and CLI version results

Do not record recovery phrases, shards, wrapping credentials, passphrases,
private path credentials, or operational secrets.

Rootless Podman using `cgroupfs` on cgroup v2 without a systemd user session is
an accepted WSL environment characteristic. It does not change the build
boundary: the builder still validates the rootless runtime, executable and
configuration hashes, explicit storage roots, pinned image digests, seccomp,
network isolation, read-only inputs, and read-only container root filesystem.
