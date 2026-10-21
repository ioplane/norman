#!/usr/bin/env bash
set -Eeuo pipefail

operation=${1:-ci}
case "$operation" in ci|build|test|validate|vet|format|lint|vuln|tidy|inside) ;; *) echo '::error::unknown check'; exit 1 ;; esac

if [[ $operation == inside ]]; then
  [[ -f /run/.containerenv ]] || { echo '::error::inside mode requires the development container'; exit 1; }
  operation=${2:?missing container check}
  mkdir -p /cache/{build,modules,tools,gotmp,evidence,lint,gopath}
  export PATH="/cache/tools:$PATH" GOBIN=/cache/tools GOTMPDIR=/cache/gotmp
  export GOTOOLCHAIN=local GOENV=off GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
  export GOCACHE=/cache/build GOMODCACHE=/cache/modules CGO_ENABLED=1
  export GOLANGCI_LINT_CACHE=/cache/lint
  export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/src
  cd /cache
  go version
  [[ $(go env GOVERSION) == go1.27.3 ]] || { echo '::error::compiler differs from reviewed Go 1.27.3'; exit 1; }
  go env GOPROXY GOSUMDB GOTOOLCHAIN CGO_ENABLED
  sha256sum /src/Containerfile.dev /src/.golangci.yml /src/go.mod /src/go.sum /src/clientbase/context_test.go /src/.github/scripts/required-tests.json
  # Detached installs retain the reviewed product module graph byte-for-byte.
  export GOFLAGS=-buildvcs=false
  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
  go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
  go install github.com/zricethezav/gitleaks/v8@v8.30.1
  for spec in 'golangci-lint github.com/golangci/golangci-lint/v2 v2.15.0' 'govulncheck golang.org/x/vuln v1.9.0' 'gitleaks github.com/zricethezav/gitleaks/v8 v8.30.1'; do
    read -r tool module version <<< "$spec"
    go version -m "/cache/tools/$tool" | tee "/cache/evidence/$tool-buildinfo.txt"
    grep -Fx "/cache/tools/$tool: go1.27.3" "/cache/evidence/$tool-buildinfo.txt"
    grep -F $'\tmod\t'"$module"$'\t'"$version"$'\t' "/cache/evidence/$tool-buildinfo.txt"
  done
  golangci-lint version
  govulncheck -version
  # Go-installed gitleaks can print a placeholder; checked buildinfo is authoritative.
  gitleaks version
  cat > /cache/check.go <<'GO'
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

func check() error {
	if len(os.Args) != 3 { return fmt.Errorf("expected mode and evidence file") }
	f, err := os.Open(os.Args[2])
	if err != nil { return err }
	defer f.Close()
	d := json.NewDecoder(f)
	switch os.Args[1] {
	case "secrets":
		var findings []json.RawMessage
		if err := d.Decode(&findings); err != nil { return err }
		if findings == nil || len(findings) != 0 { return fmt.Errorf("expected non-null zero-findings array") }
		var extra any
		if err := d.Decode(&extra); err != io.EOF { return fmt.Errorf("trailing secret evidence") }
		fmt.Println("secret findings: 0")
		return nil
	case "vulnerability-input":
		configs, sboms := 0, 0
		for {
			var event struct {
				Config *struct {
					Level string `json:"scan_level"`
					Mode string `json:"scan_mode"`
					Scanner string `json:"scanner_version"`
					Go string `json:"go_version"`
				} `json:"config"`
				SBOM *struct {
					Roots []string `json:"roots"`
					Modules []struct { Path string `json:"path"` } `json:"modules"`
				} `json:"SBOM"`
			}
			if err := d.Decode(&event); err == io.EOF { break } else if err != nil { return err }
			if event.Config != nil {
				configs++
				if event.Config.Level != "symbol" || event.Config.Mode != "source" || event.Config.Scanner != "v1.9.0" || event.Config.Go != "go1.27.3" { return fmt.Errorf("unexpected scanner configuration") }
			}
			if event.SBOM != nil {
				sboms++
				if len(event.SBOM.Roots) == 0 || len(event.SBOM.Modules) < 2 { return fmt.Errorf("empty scanner roots/modules") }
				for _, root := range event.SBOM.Roots {
					if !strings.HasPrefix(root, "github.com/rancher/norman/") { return fmt.Errorf("unexpected scanner root %s", root) }
				}
				own := false
				for _, module := range event.SBOM.Modules { if module.Path == "github.com/rancher/norman" { own = true } }
				if !own { return fmt.Errorf("Norman module absent from scanner input") }
				fmt.Printf("scanner input: roots=%d modules=%d\n", len(event.SBOM.Roots), len(event.SBOM.Modules))
			}
		}
		if configs != 1 || sboms != 1 { return fmt.Errorf("incomplete scanner stream config=%d SBOM=%d", configs, sboms) }
		return nil
	case "tests":
		b, err := os.ReadFile("/src/.github/scripts/required-tests.json")
		if err != nil { return err }
		var required struct { Package string `json:"package"`; Required []string `json:"required"`; Total int `json:"total"`; Top int `json:"top_level"` }
		if err := json.Unmarshal(b, &required); err != nil { return err }
		if required.Package != "github.com/rancher/norman/clientbase" || required.Total != 48 || required.Top != 10 || len(required.Required) != 48 { return fmt.Errorf("unexpected required test manifest") }
		runs, passes := map[string]int{}, map[string]int{}
		top, packages := 0, 0
		for {
			var event struct { Action, Package, Test string }
			if err := d.Decode(&event); err == io.EOF { break } else if err != nil { return err }
			if event.Action == "fail" || event.Action == "skip" { return fmt.Errorf("rejected %s: %s %s", event.Action, event.Package, event.Test) }
			if event.Package != required.Package { return fmt.Errorf("unexpected test package %s", event.Package) }
			if event.Test == "" { if event.Action == "pass" { packages++ }; continue }
			if event.Action == "run" { runs[event.Test]++; if !strings.Contains(event.Test, "/") { top++ } }
			if event.Action == "pass" { passes[event.Test]++ }
		}
		if len(runs) != 45 || len(passes) != 45 || top != 10 || packages != 1 { return fmt.Errorf("test input mismatch: runs=%d passes=%d top=%d packages=%d", len(runs), len(passes), top, packages) }
		seen := map[string]bool{}
		for _, name := range required.Required {
			if seen[name] || runs[name] != 1 || passes[name] != 1 { return fmt.Errorf("missing/duplicate/unpassed required test %s", name) }
			seen[name] = true
		}
		fmt.Println("critical tests: 48 run / 48 pass / 0 fail / 0 skip; 10 top-level")
		return nil
	default:
		return fmt.Errorf("unknown evidence mode")
	}
}

func main() {
	if err := check(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
GO
  go build -trimpath -o /cache/check /cache/check.go
  : > /cache/empty
  for mode in tests vulnerability-input secrets; do
    if /cache/check "$mode" /cache/empty; then echo "::error::$mode accepted empty evidence"; exit 1; fi
  done
  printf 'null\n' > /cache/null.json
  if /cache/check secrets /cache/null.json; then echo '::error::secret checker accepted null'; exit 1; fi
  printf '[extend]\nuseDefault = true\n' > /cache/gitleaks.toml
  export GOFLAGS='-mod=readonly -buildvcs=false'
  cd /src
  failed=0
  gate() {
    local label=$1 status
    local -a statuses
    shift
    echo "::group::$label"
    set +e
    "$@" 2>&1 | tee "/cache/evidence/$label.log"
    statuses=("${PIPESTATUS[@]}")
    status=${statuses[0]}
    if (( statuses[1] != 0 )); then status=${statuses[1]}; fi
    set -e
    printf '%s exit_code=%d\n' "$label" "$status" | tee -a /cache/evidence/statuses.log
    echo '::endgroup::'
    if (( status != 0 )); then failed=1; fi
  }
  module_metadata() {
    bash -euo pipefail -c '
      mkdir /cache/tidy
      git archive HEAD | tar -x -C /cache/tidy
      cd /cache/tidy
      GOFLAGS=-buildvcs=false go mod tidy
      cmp /src/go.mod go.mod
      cmp /src/go.sum go.sum
      sha256sum go.mod go.sum > /cache/evidence/tidy-first.sha256
      GOFLAGS=-buildvcs=false go mod tidy
      sha256sum -c /cache/evidence/tidy-first.sha256
      go mod verify
    '
  }
  critical_tests() {
    gate critical-tests bash -euo pipefail -c 'go test -json -race -shuffle=on -covermode=atomic -count=1 -run "^(TestContext.*|TestLegacyMalformedCA)$" ./clientbase 2> /cache/evidence/critical-tests.stderr'
    cat /cache/evidence/critical-tests.stderr
    gate critical-input /cache/check tests /cache/evidence/critical-tests.log
  }
  vulnerabilities() {
    gate vulnerability-json bash -euo pipefail -c 'govulncheck -db=https://vuln.go.dev -scan=symbol -json ./... 2> /cache/evidence/vulnerability.stderr'
    cat /cache/evidence/vulnerability.stderr
    gate vulnerability-input /cache/check vulnerability-input /cache/evidence/vulnerability-json.log
    gate vulnerabilities bash -euo pipefail -c 'govulncheck -mode=convert -show=verbose < /cache/evidence/vulnerability-json.log'
  }
  secrets() {
    if [[ -e .gitleaksignore || -L .gitleaksignore ]]; then echo '::error::source .gitleaksignore is forbidden'; return 1; fi
    git cat-file -e "$SCAN_BASE^{commit}" || return 1
    local count paths
    count=$(git rev-list --count "$SCAN_BASE..$EXPECTED_HEAD") || return 1
    (( count > 0 )) || { echo '::error::secret scan revision range has no commits'; return 1; }
    git log --format= --name-only --full-history --diff-merges=first-parent "$SCAN_BASE..$EXPECTED_HEAD" > /cache/evidence/secret-input-paths.txt || return 1
    paths=$(sed '/^$/d' /cache/evidence/secret-input-paths.txt | wc -l) || return 1
    (( paths > 0 )) || { echo '::error::secret scan revision range has no filename input'; return 1; }
    printf 'Secret input: %s..%s, commits=%s filename-events=%s; full filename-aware PR range\n' "$SCAN_BASE" "$EXPECTED_HEAD" "$count" "$paths"
    cat /cache/evidence/secret-input-paths.txt || return 1
    gitleaks git /src --log-opts="--full-history --diff-merges=first-parent $SCAN_BASE..$EXPECTED_HEAD" \
      --config=/cache/gitleaks.toml --gitleaks-ignore-path=/dev/null --ignore-gitleaks-allow \
      --redact=100 --no-banner --report-format=json --report-path=/cache/evidence/secrets.json
  }
  case "$operation" in
    ci)
      gate module-metadata module_metadata
      gate build go build -trimpath ./...
      gate example go build -trimpath -o /cache/norman ./example
      gate vet go vet ./...
      gate format golangci-lint fmt --diff ./...
      gate lint-config golangci-lint config verify
      gate lint golangci-lint run --timeout=15m ./...
      critical_tests
      vulnerabilities
      gate secrets secrets
      gate secret-input /cache/check secrets /cache/evidence/secrets.json
      ;;
    build) gate build go build -trimpath ./...; gate example go build -trimpath -o /cache/norman ./example ;;
    test) critical_tests ;;
    validate) gate vet go vet ./...; gate format golangci-lint fmt --diff ./...; gate lint-config golangci-lint config verify; gate lint golangci-lint run --timeout=15m ./... ;;
    vet) gate vet go vet ./... ;;
    format) gate format golangci-lint fmt --diff ./... ;;
    lint) gate lint-config golangci-lint config verify; gate lint golangci-lint run --timeout=15m ./... ;;
    vuln) vulnerabilities ;;
    tidy) gate module-metadata module_metadata ;;
    *) echo '::error::unknown container check'; exit 1 ;;
  esac
  du -sk /cache || failed=1
  df -Pk /cache || failed=1
  for counter in memory.max memory.peak memory.events; do
    if [[ -r /sys/fs/cgroup/$counter ]]; then printf '%s: ' "$counter"; cat "/sys/fs/cgroup/$counter" || failed=1; fi
  done
  exit "$failed"
fi

EXPECTED_HEAD=${EXPECTED_HEAD:-$(git rev-parse HEAD)}
[[ $EXPECTED_HEAD =~ ^[0-9a-f]{40}$ ]] || { echo '::error::invalid expected head'; exit 1; }
[[ $(git rev-parse HEAD) == "$EXPECTED_HEAD" ]] || { echo '::error::checkout is not requested source head'; exit 1; }
[[ -z $(git status --porcelain=v1 --untracked-files=normal) ]] || { echo '::error::checks require a clean committed source head'; exit 1; }
if [[ $operation == ci ]]; then
  [[ ${SCAN_BASE:-} =~ ^[0-9a-f]{40}$ && $SCAN_BASE != 0000000000000000000000000000000000000000 ]] || { echo '::error::ci requires the nonempty PR commit range (SCAN_BASE)'; exit 1; }
  git cat-file -e "$SCAN_BASE^{commit}"
  [[ $(git rev-list --count "$SCAN_BASE..$EXPECTED_HEAD") -gt 0 ]] || { echo '::error::secret scan revision range has no commits'; exit 1; }
fi
[[ -s Containerfile.dev && -s .golangci.yml && -s clientbase/context_test.go && -s .github/scripts/required-tests.json ]] || { echo '::error::product tooling or contract tests absent'; exit 1; }
printf 'source_head=%s operation=%s\n' "$EXPECTED_HEAD" "$operation"
command -v podman >/dev/null || { echo '::error::rootless Podman is required'; exit 1; }
[[ $(id -u) != 0 && $(podman info --format '{{.Host.Security.Rootless}}') == true ]] || { echo '::error::rootful Podman is forbidden; no sudo or socket fallback'; exit 1; }
podman version
# Worktree .git files resolve outside /src; preserve their read-only absolute paths.
git_mounts=()
if [[ -f .git ]]; then
  git_dir=$(git rev-parse --absolute-git-dir)
  common_dir=$(git rev-parse --path-format=absolute --git-common-dir)
  git_mounts+=(--volume "$common_dir:$common_dir:ro,z")
  if [[ $git_dir != "$common_dir" ]]; then git_mounts+=(--volume "$git_dir:$git_dir:ro,z"); fi
fi
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/norman-check.XXXXXXXX")
image_id=''
owner="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-${work##*/}"
cleanup() {
  local status=$? cleanup_status=0 cid
  trap - EXIT
  if [[ -s $work/cid ]]; then
    cid=$(cat "$work/cid")
    if [[ $cid =~ ^[0-9a-f]{64}$ ]] && podman container exists "$cid"; then
      if [[ $(podman inspect "$cid" --format '{{index .Config.Labels "fork.check.owner"}}') == "$owner" ]]; then
        podman inspect "$cid" --format 'container_exit={{.State.ExitCode}} oom_killed={{.State.OOMKilled}}' || cleanup_status=1
        podman stop --time=10 "$cid" || cleanup_status=1
        podman rm "$cid" || cleanup_status=1
      else cleanup_status=1; fi
    fi
  fi
  if [[ -n $image_id ]]; then
    if [[ $(podman image inspect "$image_id" --format '{{index .Config.Labels "fork.check.owner"}}') == "$owner" ]]; then
      podman image rm --no-prune "$image_id" || cleanup_status=1
    else cleanup_status=1; fi
  fi
  if [[ -d $work/cache && ! -L $work/cache ]]; then
    du -sk "$work/cache" || cleanup_status=1
    find -P "$work/cache" -type d -exec chmod u+w -- {} + || cleanup_status=1
  fi
  # Only this invocation's mktemp directory is removed on the ephemeral runner.
  rm -rf -- "$work" || cleanup_status=1
  if (( status == 0 && cleanup_status != 0 )); then status=$cleanup_status; fi
  exit "$status"
}
trap cleanup EXIT
mkdir "$work/cache"
printf '{"auths":{}}\n' > "$work/auth.json"
created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
podman build --authfile "$work/auth.json" --http-proxy=false --cpu-period=100000 --cpu-quota=400000 \
  --memory=12g --memory-swap=12g --ulimit=nproc=512:512 --cap-drop=all --security-opt=no-new-privileges \
  --build-arg "SOURCE_REVISION=$EXPECTED_HEAD" --build-arg "BUILD_CREATED=$created" \
  --label "fork.check.owner=$owner" --iidfile "$work/image-id" --file Containerfile.dev .
image_id=$(cat "$work/image-id")
[[ $image_id =~ ^sha256:[0-9a-f]{64}$ ]] || { echo '::error::unexpected built image ID'; exit 1; }
podman image inspect "$image_id" --format '{{.Id}} {{json .Config.Labels}}'
[[ $(podman image inspect "$image_id" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}') == "$EXPECTED_HEAD" ]] || { echo '::error::image revision label mismatch'; exit 1; }
[[ $(podman image inspect "$image_id" --format '{{index .Config.Labels "org.opencontainers.image.created"}}') == "$created" ]] || { echo '::error::image created label mismatch'; exit 1; }
podman run --cidfile "$work/cid" --authfile "$work/auth.json" --http-proxy=false \
  --label "fork.check.owner=$owner" --read-only --read-only-tmpfs=false --cap-drop=all --security-opt=no-new-privileges \
  --userns=keep-id --user "$(id -u):$(id -g)" --cpus=4 --memory=12g --memory-swap=12g --pids-limit=512 \
  --volume "$work/cache:/cache:rw,z" --tmpfs /tmp:rw,nosuid,nodev,size=512m,mode=1777 \
  --volume "$PWD:/src:ro,z" "${git_mounts[@]}" --workdir /src \
  --env "EXPECTED_HEAD=$EXPECTED_HEAD" --env "SCAN_BASE=${SCAN_BASE:-}" \
  --env GOPROXY=https://proxy.golang.org --env GOSUMDB=sum.golang.org \
  --env GOMAXPROCS=4 --env GOTMPDIR=/cache/gotmp --env GOPATH=/cache/gopath \
  "$image_id" bash /src/.github/scripts/fork-check.sh inside "$operation"
