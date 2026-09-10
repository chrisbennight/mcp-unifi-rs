## Change type

- [ ] Tool contract / behavior
- [ ] Authentication / authorization boundary
- [ ] UniFi controller API compatibility
- [ ] Container image or runtime
- [ ] Workflow / CI
- [ ] Dependency update
- [ ] Documentation only

## Design goal

What this change achieves and why.

## Acceptance criteria

- Observable behavior that defines success.

## Change narrative

### What changed and why

Describe the code, schema, normalization, policy classification, and
documentation changes.

### Security and information flow

Describe caller authentication, gateway authorization, controller credential
use, upstream requests, model-visible fields, and excluded sensitive fields.

### Upstream assumptions

Record the targeted UniFi Network release(s), API generation (Integration API
versus legacy), and primary upstream references.

## Verification performed

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --workspace --all-features --locked`
- [ ] `cargo doc --workspace --no-deps --locked`
- [ ] `python3 scripts/check_docs.py`
- [ ] `python3 -m unittest discover -s scripts/tests`
- [ ] Container builds and passes its native healthcheck when runtime files changed

## Risk assessment

### Secrets and exposure

Explain changes to secrets, configuration/log/runtime-data exposure, PII, or
network reachability.

### Mutation semantics

Explain validation, preview/confirm, idempotency, retry behavior, read-back
verification, and ambiguous outcomes. State `Not applicable` for read-only
changes.

### Open questions

List unresolved assumptions or state `None`.

## Non-goals

State what this pull request deliberately leaves out.
