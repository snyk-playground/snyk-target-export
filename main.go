// snyk-refresh discovers all existing SCM targets in a Snyk group and writes
// a refresh-import-targets.json file that snyk-api-import can consume to
// re-import those targets (e.g. to add SCA scanning to existing Snyk Code projects).
//
// No SCM credentials required -- only SNYK_TOKEN.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sam1el/snyk-refresh/internal"
)

// Set by GoReleaser ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// OrgMeta holds display metadata for an org in the output JSON.
type OrgMeta struct {
	Name string `json:"name,omitempty"`
	Slug string `json:"slug,omitempty"`
}

// RefreshOutput is the JSON structure written to the output file.
type RefreshOutput struct {
	GroupID      string                  `json:"groupId,omitempty"`
	Orgs         map[string]OrgMeta      `json:"orgs"`
	Integrations map[string]string       `json:"integrations"`
	Targets      []internal.ImportTarget `json:"targets"`
}

func main() {
	showVersion := flag.Bool("version", false, "Print version information and exit")
	groupID := flag.String("groupId", "", "Snyk group ID (all orgs in this group will be scanned)")
	orgID := flag.String("orgId", "", "Single Snyk org ID to scan (alternative to --groupId)")
	integrationType := flag.String("integrationType", "", "Filter to a specific integration type (e.g. github-cloud-app)")
	concurrency := flag.Int("concurrency", 5, "Number of orgs to process in parallel")
	output := flag.String("output", "refresh-import-targets.json", "Output file path")
	flag.Parse()

	if *showVersion {
		fmt.Printf("snyk-refresh %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	// Validate flags
	if *groupID == "" && *orgID == "" {
		fmt.Fprintln(os.Stderr, "Error: either --groupId or --orgId is required")
		flag.Usage()
		os.Exit(1)
	}
	if *groupID != "" && *orgID != "" {
		fmt.Fprintln(os.Stderr, "Error: provide either --groupId or --orgId, not both")
		flag.Usage()
		os.Exit(1)
	}

	token, err := internal.GetSnykToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	client := internal.NewHTTPClient()

	// Resolve orgs
	var orgs []internal.Org
	if *groupID != "" {
		log.Printf("Fetching organizations for group %s...", *groupID)
		orgs, err = internal.FetchOrgs(ctx, client, token, *groupID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching orgs: %v\n", err)
			os.Exit(1)
		}
	} else {
		orgs = []internal.Org{{ID: *orgID}}
	}

	log.Printf("Processing %d organization(s) with concurrency %d...", len(orgs), *concurrency)

	// Process orgs concurrently
	type orgResult struct {
		targets     []internal.ImportTarget
		orgMeta     map[string]OrgMeta
		intMeta     map[string]string
		gitlabCount int
		err         error
		orgID       string
		orgLabel    string
	}

	results := make(chan orgResult, len(orgs))
	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup

	for _, org := range orgs {
		wg.Add(1)
		go func(o internal.Org) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			label := o.ID
			if o.Name != "" {
				label = fmt.Sprintf("%s (%s)", o.Name, o.Slug)
			}

			res := orgResult{
				orgID:    o.ID,
				orgLabel: label,
				orgMeta:  make(map[string]OrgMeta),
				intMeta:  make(map[string]string),
			}

			// Store org metadata
			if o.Name != "" || o.Slug != "" {
				res.orgMeta[o.ID] = OrgMeta{Name: o.Name, Slug: o.Slug}
			}

			// Fetch integrations and projects in parallel
			var integrations map[string]string
			var projects []internal.Project
			var intErr, projErr error
			var innerWg sync.WaitGroup

			innerWg.Add(2)
			go func() {
				defer innerWg.Done()
				integrations, intErr = internal.ListIntegrations(ctx, client, token, o.ID)
			}()
			go func() {
				defer innerWg.Done()
				projects, projErr = internal.FetchProjects(ctx, client, token, o.ID)
			}()
			innerWg.Wait()

			if intErr != nil {
				res.err = fmt.Errorf("list integrations: %w", intErr)
				results <- res
				return
			}
			if projErr != nil {
				res.err = fmt.Errorf("fetch projects: %w", projErr)
				results <- res
				return
			}

			// Store integration metadata
			for intType, intID := range integrations {
				res.intMeta[intID] = intType
			}

			if len(projects) == 0 {
				results <- res
				return
			}

			// Convert projects to import targets
			seen := make(map[string]bool)
			gitlabSkipped := 0

			for _, p := range projects {
				// Count gitlab projects for warning
				if p.Origin == "gitlab" {
					gitlabSkipped++
					continue
				}

				// Filter to SCM origins
				if !internal.IsSCMOrigin(p.Origin) {
					continue
				}

				// Filter by integration type if specified
				if *integrationType != "" && p.Origin != *integrationType {
					// Also check the mapped key for bitbucket-connect-app
					if internal.OriginToIntegrationKey(p.Origin) != *integrationType {
						continue
					}
				}

				// Look up integration ID
				intKey := internal.OriginToIntegrationKey(p.Origin)
				integrationID, ok := integrations[intKey]
				if !ok || integrationID == "" {
					continue
				}

				// Convert project to target
				branch := p.Branch
				if branch == "" {
					branch = p.TargetReference
				}
				target, ok := internal.ProjectToTarget(p.Name, p.Origin, branch)
				if !ok {
					continue
				}

				// Deduplicate
				tid := internal.TargetID(o.ID, integrationID, target)
				if seen[tid] {
					continue
				}
				seen[tid] = true

				res.targets = append(res.targets, internal.ImportTarget{
					Target:        target,
					OrgID:         o.ID,
					IntegrationID: integrationID,
				})
			}

			res.gitlabCount = gitlabSkipped
			results <- res
		}(org)
	}

	// Close results channel when all goroutines finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	out := RefreshOutput{
		Orgs:         make(map[string]OrgMeta),
		Integrations: make(map[string]string),
	}
	if *groupID != "" {
		out.GroupID = *groupID
	}

	failedOrgs := 0
	processedOrgs := 0

	for res := range results {
		if res.err != nil {
			failedOrgs++
			log.Printf("WARNING: Failed to process org %s: %v", res.orgLabel, res.err)
			continue
		}

		processedOrgs++

		if res.gitlabCount > 0 {
			log.Printf("WARNING: Org %s: skipping %d GitLab project(s) -- Snyk API does not provide numeric GitLab project ID required for re-import",
				res.orgLabel, res.gitlabCount)
		}

		if len(res.targets) > 0 {
			log.Printf("Org %s: %d target(s)", res.orgLabel, len(res.targets))
		} else if len(res.targets) == 0 && res.gitlabCount == 0 {
			log.Printf("Org %s: no SCM projects found", res.orgLabel)
		}

		out.Targets = append(out.Targets, res.targets...)

		for k, v := range res.orgMeta {
			out.Orgs[k] = v
		}
		for k, v := range res.intMeta {
			out.Integrations[k] = v
		}
	}

	// Write output
	if len(out.Targets) == 0 {
		log.Println("No targets found to refresh.")
	}

	jsonData, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	// Sanitize the output path to prevent path traversal
	sanitizedOutput, err := sanitizeOutputPath(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid output path: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(sanitizedOutput, jsonData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nTotal: %d target(s) across %d org(s)", len(out.Targets), processedOrgs)
	if failedOrgs > 0 {
		fmt.Printf(" (%d org(s) failed)", failedOrgs)
	}
	fmt.Printf("\nOutput written to: %s\n", sanitizedOutput)
	fmt.Println("\nTo import, run:")
	fmt.Printf("  snyk-api-import import --file=%s\n", sanitizedOutput)
}

// sanitizeOutputPath validates and resolves the output file path to prevent
// path traversal attacks. It ensures the resolved path stays within the
// current working directory or is an absolute path without traversal.
func sanitizeOutputPath(p string) (string, error) {
	// Clean the path (resolves .., ., double slashes)
	cleaned := filepath.Clean(p)

	// Reject paths that try to traverse above the working directory
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("path contains directory traversal: %s", p)
	}

	// If relative, resolve against CWD
	if !filepath.IsAbs(cleaned) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get working directory: %w", err)
		}
		cleaned = filepath.Join(cwd, cleaned)
	}

	return cleaned, nil
}
