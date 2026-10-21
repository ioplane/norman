Norman
========

An API framework for Building [Rancher Style APIs](https://github.com/rancher/api-spec/) backed by K8s CustomResources and their controllers.

## Example

Refer to https://github.com/rancher/go-skel for skeleton norman controller projects

## License
Copyright (c) 2014-2017 [Rancher Labs, Inc.](http://rancher.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# Versioning

See [VERSION.md](VERSION.md).

# Releasing

Releases are cut by triggering the [Cut release workflow](.github/workflows/cut-release.yaml)
from the GitHub Actions tab. Select the appropriate release branch (e.g. `release/v0.5`)
and provide the version (e.g. `v0.5.1`) as input. The workflow validates the version
against [VERSION.md](VERSION.md), creates the annotated tag, and dispatches the
[On release workflow](.github/workflows/release.yaml) on the new tag, which creates
the GitHub release.

## ioplane fork: request contexts

This fork adds `clientbase.NewAPIClientContext`, `APIOperations.DoGetContext`,
and `APIOperations.DoByIDContext`. Existing entry points and generated interfaces
remain available. Contexts govern constructor schema discovery and individual
GET requests, including response body reads. A context is never stored in the
returned client; canceling construction after success does not cancel later
operations. Cancellation during CPU JSON decoding is checked after decoding,
not by interrupting the decoder.

Pass a non-nil context. The caller must exclusively own `ClientOpts` and any
supplied `HTTPClient` during construction: construction sets the timeout and
replaces the transport. Concurrent construction with a shared client is not
supported. After construction, do not mutate the published options, client,
transport, schema map, or dialer while operations are running. Individual GET
contexts do not change those fields. Malformed nonempty `CACerts` now fails
before network access in both constructors, including when `Insecure` is true.

Development uses the digest-pinned Go 1.27.3 `Containerfile.dev`; the module's
Go 1.26.0 floor, dependency graph and checksums remain unchanged. Install only
rootless Podman, Git and Make on the host. After the own-fork CI control change
is present, run `SCAN_BASE=<reviewed-base-sha> make ci` for all checks, or
`make build`, `make test`,
`make vet`, `make format`, `make lint`, `make vuln` and `make tidy` for individual
checks. `make validate` runs vet, format and lint. Format is check-only; tidy
runs twice in a private archive and fails on changes to `go.mod` or `go.sum`.
Each invocation builds the checked-out development image, mounts source read-only,
and removes only its own ephemeral container, image and cache. Outputs, including
the example binary, are temporary. No host Go tools or persistent volumes are used.
The optional `compose.yaml` dev shell uses the same Containerfile without a socket.

The dispatcher sets `GOPROXY=https://proxy.golang.org` and
`GOSUMDB=sum.golang.org` explicitly. Exact-version tools are installed outside
the product module and their Go build information is checked; no tool dependencies
are added to the retained module graph. golangci-lint v2 runs all linters and
checks gofumpt/goimports formatting across the module, including tests and
generated files, without diff filters or exclusion presets. Existing findings
remain blocking and visible; this tooling change does not assert a clean baseline
or reformat untouched code. Tests bind the 36 required context cases (10 top-level)
to actual race-enabled JSON events; the full module is built and vetted.

Only same-repository pull requests to `fork/release-v0.9` run the own-fork
Blacksmith job. Inherited Rancher CI/release/Vault jobs are guarded for
`rancher/norman`. Before enabling Actions, the fork owner must publish the guarded
CI control branch and switch the own default to it; keep old main and backup refs.
The own job receives read-only contents permission and no upstream credentials.

These APIs and checks do not establish provider SDK cancellation, whole-module
ABI, performance, live integration or production acceptance. No fork release
is declared here.
