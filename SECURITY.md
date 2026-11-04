# Security policy

agent-scope is a security component, so reports are very welcome.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting
(*Security → Report a vulnerability*) on this repository. Include a minimal policy/catalog and
the request that is decided incorrectly, or the steps to reproduce.

You will get an acknowledgement within a few days. Fixes for confirmed issues come with a
regression scenario in `examples/acme/eval/` or `spec/vectors/` so they stay fixed.

## Scope

In scope: any way to get an `allow` (or a forwarded call) that the documented semantics say must
be denied, token validation bypasses, audit log forgery that `agent-scope audit verify` does not
detect, and crashes of the gateway triggered by remote input.

Out of scope: the limitations listed in [docs/threat-model.md](docs/threat-model.md#out-of-scope),
and anything that requires `--dev`.

## Supported versions

Only the latest release on `main` receives fixes while the project is pre-1.0.
