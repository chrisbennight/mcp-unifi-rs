# Contributing

Start with an issue that describes the task a UniFi operator needs to perform,
the current behavior, and the expected result. For a bug, include application
versions, the transport and surface, a minimal tool call, and redacted output.
Do not include credentials, Wi-Fi passwords, voucher codes, or private
controller inventories. See [support](SUPPORT.md) and [security](SECURITY.md).

## Local setup

Install Rust 1.98.1 with rustfmt and clippy, Python 3.11 or later, and your
platform's native build tools. Docker is needed for image validation, not for
the Rust unit and integration tests. Clone the repository and run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --no-deps --locked
python3 scripts/check_docs.py
python3 -m unittest discover -s scripts/tests
```

The tests use loopback fakes and synthetic credentials. They need no real
controller, gateway, secret provider, or private registry. Dependency downloads
use public registries unless you configure a local mirror. Keep `Cargo.lock`
committed; use `--locked` when verifying a candidate.

To check a runtime or image change:

```sh
python3 scripts/check_build_context.py
docker build --check .
docker build -t mcp-unifi-rs:test .
python3 scripts/smoke_image.py mcp-unifi-rs:test
```

CI also parses both Compose examples with fake bearer credentials. The
documentation validator checks local links, heading anchors, JSON examples,
and that each production environment setting appears in the reference.

The image tests start Network and Protect with fake credentials and no external
network, check liveness, and remove their containers. They do not verify live
controller compatibility. Manual [evaluation tasks](docs/evals.md) are separate
and require an operator's explicit permission for any real-network changes.

## Making a change

Keep a pull request focused on a complete behavior. Search for an existing
abstraction before adding one. Add a regression test that fails without the
fix, and update examples or documentation when a contract changes. Preserve
bounds, redaction, mutation previews, and explicit uncertain outcomes.

The [architecture](docs/architecture.md) explains the crate boundaries; the
[tool reference](docs/tool-surface.md) and registry define the public tool
surface. Adding a public API endpoint does not require exposing it as a new
MCP tool. Avoid introducing controller-specific details into the client flow
unless they help the operator make a decision.

## Pull requests

Fill the PR template with the problem, resulting behavior, and verification.
Authentication, authorization, credential, and disclosure changes must select
the corresponding change type. CI checks source and container behavior. A
maintainer requests AERB review; contributors do not need access to a private
gateway to submit or test their changes.

Required checks and review apply to the current commit. Resolve or explicitly
disposition each finding before merging. The initial PR body is retained as
the review record; post corrections in comments. Additional repository rules
are in [AGENTS.md](AGENTS.md).

Use plain language in documentation. Put the reader's task first, give complete
commands, and distinguish observed behavior from assumptions. Claims about
compatibility or other projects need evidence. Helpful references are
[Open Source Guides](https://opensource.guide/starting-a-project/),
[Diátaxis](https://diataxis.fr/start-here/), and
[Google's tone guidance](https://developers.google.com/style/tone).

For artwork or README changes, follow the [visual identity and writing guide](docs/branding/README.md).
Keep editable artwork and exports together, run the export check, and inspect
both themes and small sizes. Add new pages to the [documentation guide](docs/README.md)
when they help readers find a task.
