# Trivy Security Scan Action

This composite action runs Trivy through `aquasecurity/trivy-action` with defaults that work for repository scans and GitHub code scanning.

## Inputs

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `scan-type` | Trivy scan type: `fs`, `image`, `repo`, `rootfs`, or `config`. | No | `fs` |
| `scan-ref` | Path, repository URL, image reference, rootfs path, or SBOM file to scan. | No | `.` |
| `image-ref` | Container image to scan. Overrides `scan-ref` and uses image scanning when provided. | No | `""` |
| `scanners` | Comma-separated scanners to run. | No | `vuln,secret,misconfig` |
| `severity` | Comma-separated severities to report. | No | `CRITICAL,HIGH` |
| `vuln-type` | Comma-separated vulnerability types to scan. | No | `os,library` |
| `ignore-unfixed` | Ignore vulnerabilities without a fixed version. | No | `true` |
| `format` | Trivy output format. Use `sarif` for GitHub code scanning. | No | `sarif` |
| `output` | Path to write the Trivy report. Leave empty to print to the job log. | No | `trivy-results.sarif` |
| `exit-code` | Exit code when findings match the configured filters. | No | `1` |
| `trivyignores` | Comma-separated `.trivyignore` files. | No | `""` |
| `skip-dirs` | Comma-separated directories to skip. | No | `""` |
| `skip-files` | Comma-separated files to skip. | No | `""` |
| `upload-sarif` | Upload SARIF results to GitHub code scanning when possible. | No | `true` |
| `limit-severities-for-sarif` | Respect the severity input when producing SARIF output. | No | `true` |

## Repository scan

```yaml
name: Trivy

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run Trivy
        uses: eliuma/dev-actions/trivy-scan@main
        with:
          scan-type: fs
          scan-ref: .
```

## Container image scan

```yaml
name: Trivy image

on:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  scan-image:
    runs-on: ubuntu-latest
    steps:
      - name: Scan image
        uses: eliuma/dev-actions/trivy-scan@main
        with:
          image-ref: ghcr.io/OWNER/IMAGE:TAG
```

Set `exit-code: "0"` if you want the workflow to publish results without failing the build.