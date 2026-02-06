# snyk-refresh

Generate an import targets file from your existing Snyk projects so you can re-import them with [snyk-api-import](https://github.com/snyk/snyk-api-import). This is useful when you need to add a new Snyk product (e.g. SCA) to projects that were originally imported for a different product (e.g. Snyk Code).

`snyk-refresh` scans all organizations in a Snyk group, discovers every SCM target that already exists, and writes a `refresh-import-targets.json` file. You then feed that file to `snyk-api-import import` to trigger the re-import.

No SCM credentials are required. The tool only communicates with Snyk APIs using your `SNYK_TOKEN`.

## Quick Start

```bash
export SNYK_TOKEN=<your-snyk-api-token>

# 1. Generate the import targets file
./snyk-refresh --groupId=<your-group-id>

# 2. Review the output
cat refresh-import-targets.json

# 3. Import via snyk-api-import
snyk-api-import import --file=refresh-import-targets.json
```

## Installation

### Download a release

Download the binary for your platform from the [Releases](https://github.com/sam1el/snyk-refresh/releases) page. Archives are available for Linux, macOS, and Windows on both amd64 and arm64 architectures.

### Build from source

```bash
git clone https://github.com/sam1el/snyk-refresh.git
cd snyk-refresh
make build
```

The `Makefile` includes several useful targets:

| Target | Description |
|--------|-------------|
| `make build` | Build the binary with version info embedded |
| `make test` | Run tests with race detection |
| `make lint` | Check formatting and run `go vet` |
| `make fmt` | Auto-format all Go source files |
| `make check` | Run fmt, lint, and test together |
| `make snapshot` | Build a local GoReleaser snapshot (no publish) |
| `make clean` | Remove built binaries and dist/ |

## Prerequisites

- A Snyk API token with access to the group or organization you want to scan
- [snyk-api-import](https://github.com/snyk/snyk-api-import) installed (for the import step)

## Usage

### Scan all organizations in a group

```bash
./snyk-refresh --groupId=<your-group-id>
```

### Scan a single organization

```bash
./snyk-refresh --orgId=<your-org-id>
```

### Filter to a specific integration type

Only include targets from a particular SCM integration:

```bash
./snyk-refresh --groupId=<your-group-id> --integrationType=github-cloud-app
```

### Control concurrency

Adjust how many organizations are processed in parallel (default: 5):

```bash
./snyk-refresh --groupId=<your-group-id> --concurrency=10
```

### Write output to a custom location

```bash
./snyk-refresh --groupId=<your-group-id> --output=/path/to/targets.json
```

### Check the version

```bash
./snyk-refresh --version
```

## Options

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--groupId` | One of groupId or orgId | | Snyk group ID. All orgs in this group will be scanned. |
| `--orgId` | One of groupId or orgId | | Single Snyk org ID to scan. |
| `--integrationType` | No | all types | Filter to a specific integration type (e.g. `github-cloud-app`). |
| `--concurrency` | No | `5` | Number of organizations to process in parallel. |
| `--output` | No | `refresh-import-targets.json` | Output file path. |
| `--version` | No | | Print version information and exit. |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SNYK_TOKEN` | Yes | Snyk API token (also accepts `SNYK_API_TOKEN`). |
| `SNYK_API` | No | Override the Snyk API base URL (e.g. `https://api.eu.snyk.io` for EU deployments). Also accepts `SNYK_API_URL`. |

## Supported Integrations

- GitHub
- GitHub Cloud App
- GitHub Enterprise
- Bitbucket Cloud
- Bitbucket Cloud App
- Bitbucket Connect App
- Bitbucket Server
- Azure Repos

GitLab projects are skipped because the Snyk API does not return the numeric GitLab project ID that the import API requires. A warning is printed when GitLab projects are found.

## How It Works

1. Fetches all organizations in the specified group (or uses the single org provided)
2. For each organization, fetches integrations and projects in parallel
3. Filters to SCM-based projects
4. Converts each project into an import target, preserving custom branch configurations
5. Deduplicates targets so each unique repo+branch combination is listed once
6. Writes the results to a JSON file

The output file includes metadata to make it easy to review:

```json
{
  "groupId": "<your-group-id>",
  "orgs": {
    "<org-id>": { "name": "My Org", "slug": "my-org" }
  },
  "integrations": {
    "<integration-id>": "github-cloud-app"
  },
  "targets": [
    {
      "target": { "owner": "my-org", "name": "my-repo", "branch": "main" },
      "orgId": "<org-id>",
      "integrationId": "<integration-id>"
    }
  ]
}
```

## Branch Handling

Custom branch configurations are preserved. If a project in Snyk monitors a non-default branch, that branch is included in the target. Each unique repo+branch combination is treated as a separate target.

When a project has no custom branch set, the import will use the repository's default branch.

## Example: Adding SCA to Existing Snyk Code Projects

```bash
export SNYK_TOKEN=<your-snyk-api-token>

# Step 1: Discover all existing targets
./snyk-refresh --groupId=<your-group-id>

# Step 2: Review the file
# (check refresh-import-targets.json to confirm targets look correct)

# Step 3: Re-import to trigger SCA scanning
snyk-api-import import --file=refresh-import-targets.json
```

## Releasing

Releases are automated via [GoReleaser](https://goreleaser.com/) and GitHub Actions. To create a new release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The [Release workflow](.github/workflows/release.yml) will build binaries for all supported platforms, generate a changelog, and publish a GitHub Release.

## License

Apache-2.0
