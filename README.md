# Trivy Security Scan Action

Runs Trivy once, then renders the result three ways: a Markdown report in the job
summary, SARIF uploaded to GitHub code scanning, and the raw JSON as a run artifact.

Findings are grouped by the **image layer that introduced them**, with the
Dockerfile instruction that built that layer and the command that fixes it — so
a CVE points at the line of the Dockerfile that owns it.

```markdown
## Trivy scan - `ghcr.io/Davewst/py-dev-1:latest`

**5 findings** - 2 critical, 2 high, 1 medium. 4 of 5 vulnerabilities have a published fix.

### Layer 2 - `RUN apk add --no-cache curl ca-certificates bash && update-ca-certificates`
2 findings - 2 fixable - `alpine` packages

| Package | Installed | Fixed in | Severity | ID |
|---|---|---|---|---|
| `openssl` | 3.1.4-r5 | 3.1.4-r6 | CRITICAL | CVE-2025-1111 |
| `curl`    | 8.5.0-r0 | 8.6.0-r0 | HIGH     | CVE-2025-2222 |

**Fix:** `apk add --no-cache --upgrade curl>=8.6.0-r0 openssl>=3.1.4-r6`

### Layer 4 - `RUN pip install --no-cache-dir -r requirements.txt`
2 findings - 2 fixable - `python-pkg` packages

**Fix:** `pin in requirements.txt -> flask>=3.0.3 werkzeug>=3.0.6`
```

Layer attribution comes from the image config history: each finding's `DiffID`
is matched to the instruction that created it, skipping metadata-only layers.
Filesystem scans have no layers, so those findings group under one section.

A scan that fails to produce a report is reported as a failed scan and exits 1 —
it is never rendered as "clean", so a scan that did not run cannot look like an
image with no findings.

## Inputs

| Name | Description | Default |
|------|-------------|---------|
| `scan-type` | `fs`, `image`, `repo`, `rootfs`, or `config`. | `fs` |
| `scan-ref` | Path or target to scan when `image-ref` is empty. | `.` |
| `image-ref` | Container image to scan. Overrides `scan-ref`. | `""` |
| `scanners` | Comma-separated scanners to run. | `vuln,secret,misconfig` |
| `severity` | Comma-separated severities to report. | `CRITICAL,HIGH` |
| `ignore-unfixed` | Ignore vulnerabilities with no published fix. | `false` |
| `exit-code` | Set to `0` to report findings without failing the job. | `1` |
| `trivyignores` | Comma-separated `.trivyignore` files. | `""` |
| `upload-sarif` | Also upload to code scanning. Needs `security-events: write`. | `true` |
| `artifact-name` | Report artifact name. Must be unique within a run. | `trivy-report` |

## Outputs

| Name | Description |
|------|-------------|
| `total` | Total findings. |
| `critical` / `high` | Counts for those severities. |
| `fixable` | Vulnerabilities with a published fix. |
| `report` | Path to the rendered Markdown report (`trivy-report.md`). |

## Repository scan

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Davewst/Update@master
        with:
          scan-type: fs
          scan-ref: .
```

## Container image scan

```yaml
permissions:
  contents: read
  packages: read
  security-events: write

jobs:
  scan-image:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: Davewst/Update@master
        with:
          image-ref: ghcr.io/OWNER/IMAGE:TAG
          exit-code: "0"      # report without failing a post-push scan
          artifact-name: trivy-my-image
```

`security-events: write` is required whenever `upload-sarif` is left on.
When a workflow runs more than one scan, give each a distinct `artifact-name`.

## Fleet usage

| Repo | Workflow | Scans |
|------|----------|-------|
| `Docker-image` | `py-container-scan.yml` | `python-image:latest` |
| `Docker-image` | `node-container-scan.yml` | `node-image:latest` |
| `py-dev-1` | `container-scan.yml` | `py-dev-1:latest` |
| `py-dev-1` | `pr-test-build.yml` | app built on a candidate base (PR gate) |
| `node-dev-2` | `node-container-scan.yml` | `node-dev-2:latest` |
| `node-dev-2` | `base-build-check.yml` | app built on a candidate base (PR gate) |
| `Update` | `trivy-scan.yml` | repo filesystem |
| `app-reports` | `trivy-scan.yml` | repo filesystem |
