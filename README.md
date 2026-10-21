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

Development uses `Containerfile.dev`, pinned to Go 1.27.3, with the module's
Go 1.26.0 floor and dependency graph retained. Run focused
`go test -race ./clientbase` and `go vet ./clientbase` inside the project
development container, with explicit runtime environment
`GOPROXY=https://proxy.golang.org` and `GOSUMDB=sum.golang.org`.
The inherited Makefile's lint v1 target is not the fork acceptance gate; a
separate tooling change must provide the v2 gate before delivery. These APIs do
not establish provider SDK cancellation, whole-module ABI, performance, or
production acceptance. No fork release is declared here.
