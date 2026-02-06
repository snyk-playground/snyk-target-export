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
	"sort"
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
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "dedup":
			runDedup(os.Args[2:])
			return
		case "--version", "-version":
			fmt.Printf("snyk-refresh %s (commit: %s, built: %s)\n", version, commit, date)
			return
		}
	}
	runRefresh(os.Args[1:])
}

// runRefresh implements the existing refresh subcommand (default behavior).
func runRefresh(args []string) {
	fs := flag.NewFlagSet("refresh", flag.ExitOnError)
	showVersion := fs.Bool("version", false, "Print version information and exit")
	groupID := fs.String("groupId", "", "Snyk group ID (all orgs in this group will be scanned)")
	orgID := fs.String("orgId", "", "Single Snyk org ID to scan (alternative to --groupId)")
	integrationType := fs.String("integrationType", "", "Filter to a specific integration type (e.g. github-cloud-app)")
	concurrency := fs.Int("concurrency", 5, "Number of orgs to process in parallel")
	output := fs.String("output", "refresh-import-targets.json", "Output file path")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("snyk-refresh %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	// Validate flags
	if *groupID == "" && *orgID == "" {
		fmt.Fprintln(os.Stderr, "Error: either --groupId or --orgId is required")
		fs.Usage()
		os.Exit(1)
	}
	if *groupID != "" && *orgID != "" {
		fmt.Fprintln(os.Stderr, "Error: provide either --groupId or --orgId, not both")
		fs.Usage()
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

// duplicateGroup holds a set of projects that share the same name+origin key,
// sorted by creation timestamp. The first entry is the "original" (oldest);
// the rest are duplicates.
type duplicateGroup struct {
	key      string
	projects []internal.Project
}

// runDedup implements the dedup subcommand: find (and optionally delete)
// duplicate projects within Snyk organizations.
func runDedup(args []string) {
	fs := flag.NewFlagSet("dedup", flag.ExitOnError)
	groupID := fs.String("groupId", "", "Snyk group ID (all orgs in this group will be scanned)")
	orgID := fs.String("orgId", "", "Single Snyk org ID to scan")
	concurrency := fs.Int("concurrency", 5, "Number of orgs to process in parallel")
	doDelete := fs.Bool("delete", false, "Actually delete duplicates (default is dry-run)")
	debug := fs.Bool("debug", false, "Print detailed project info for debugging")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *groupID == "" && *orgID == "" {
		fmt.Fprintln(os.Stderr, "Error: either --groupId or --orgId is required")
		fs.Usage()
		os.Exit(1)
	}
	if *groupID != "" && *orgID != "" {
		fmt.Fprintln(os.Stderr, "Error: provide either --groupId or --orgId, not both")
		fs.Usage()
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

	if !*doDelete {
		log.Println("DRY RUN -- no projects will be deleted. Use --delete to remove duplicates.")
	}

	log.Printf("Scanning %d organization(s) for duplicates with concurrency %d...", len(orgs), *concurrency)

	// Process orgs concurrently
	type dedupResult struct {
		orgID        string
		orgLabel     string
		groups       []duplicateGroup
		projectCount int
		err          error
	}

	results := make(chan dedupResult, len(orgs))
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

			res := dedupResult{
				orgID:    o.ID,
				orgLabel: label,
			}

			projects, err := internal.FetchProjects(ctx, client, token, o.ID)
			if err != nil {
				res.err = fmt.Errorf("fetch projects: %w", err)
				results <- res
				return
			}

			res.projectCount = len(projects)
			log.Printf("Org %s: fetched %d project(s)", label, len(projects))

			if *debug {
				for _, p := range projects {
					log.Printf("  [DEBUG] id=%s name=%q origin=%q created=%q", p.ID, p.Name, p.Origin, p.Created)
				}
			}

			// Group projects by name only -- duplicates from re-imports
			// often have different origins (e.g. bitbucket-connect-app
			// vs bitbucket-cloud) so origin must not be part of the key.
			grouped := make(map[string][]internal.Project)
			for _, p := range projects {
				grouped[p.Name] = append(grouped[p.Name], p)
			}

			// Find groups with duplicates
			for key, projs := range grouped {
				if len(projs) < 2 {
					continue
				}
				// Sort by Created ascending (oldest first)
				sort.Slice(projs, func(i, j int) bool {
					return projs[i].Created < projs[j].Created
				})
				res.groups = append(res.groups, duplicateGroup{
					key:      key,
					projects: projs,
				})
			}

			results <- res
		}(org)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results per org for two-phase processing:
	// Phase 1: delete duplicate projects
	// Phase 2: find and delete orphaned empty targets
	type collectedResult struct {
		orgID    string
		orgLabel string
		groups   []duplicateGroup
	}
	var orgsWithDuplicates []collectedResult
	failedOrgs := 0

	for res := range results {
		if res.err != nil {
			failedOrgs++
			log.Printf("WARNING: Failed to process org %s: %v", res.orgLabel, res.err)
			continue
		}
		if len(res.groups) > 0 {
			orgsWithDuplicates = append(orgsWithDuplicates, collectedResult{
				orgID:    res.orgID,
				orgLabel: res.orgLabel,
				groups:   res.groups,
			})
		}
	}

	// Phase 1: Report and optionally delete duplicate projects
	totalDuplicates := 0
	totalDeleted := 0
	totalFailed := 0
	orgsAffected := make(map[string]bool)

	for _, res := range orgsWithDuplicates {
		orgsAffected[res.orgID] = true
		fmt.Printf("\nOrg: %s\n", res.orgLabel)

		for _, g := range res.groups {
			original := g.projects[0]
			dupes := g.projects[1:]
			totalDuplicates += len(dupes)

			fmt.Printf("  DUPLICATE  %s\n", original.Name)
			fmt.Printf("    keep:    %s  origin=%s  created %s\n", original.ID, original.Origin, original.Created)

			for _, d := range dupes {
				if *doDelete {
					err := internal.DeleteProject(ctx, client, token, res.orgID, d.ID)
					if err != nil {
						totalFailed++
						fmt.Printf("    FAILED:  %s  origin=%s  created %s  error: %v\n", d.ID, d.Origin, d.Created, err)
					} else {
						totalDeleted++
						fmt.Printf("    deleted: %s  origin=%s  created %s\n", d.ID, d.Origin, d.Created)
					}
				} else {
					fmt.Printf("    delete:  %s  origin=%s  created %s\n", d.ID, d.Origin, d.Created)
				}
			}
		}
	}

	// Phase 2: Find and clean up empty duplicate targets.
	// After project deletion, targets that had all their projects removed
	// become empty shells. Fetch all targets (including empty) and delete
	// duplicates that have no projects.
	targetsDeleted := 0
	targetsFailed := 0

	if len(orgsAffected) > 0 {
		if *doDelete {
			fmt.Println("\nCleaning up empty duplicate targets...")
		} else if totalDuplicates > 0 {
			fmt.Println("\nEmpty duplicate targets that would be removed:")
		}

		for orgID := range orgsAffected {
			targets, err := internal.FetchTargets(ctx, client, token, orgID)
			if err != nil {
				log.Printf("WARNING: Could not fetch targets for org %s: %v", orgID, err)
				continue
			}

			// Build a set of target IDs that still have projects
			activeTargets := make(map[string]bool)
			projects, err := internal.FetchProjects(ctx, client, token, orgID)
			if err != nil {
				log.Printf("WARNING: Could not re-fetch projects for org %s: %v", orgID, err)
				continue
			}
			for _, p := range projects {
				if p.TargetID != "" {
					activeTargets[p.TargetID] = true
				}
			}

			// Group targets by display_name
			targetsByName := make(map[string][]internal.APITarget)
			for _, t := range targets {
				targetsByName[t.DisplayName] = append(targetsByName[t.DisplayName], t)
			}

			// For each name with multiple targets, delete the empty ones
			for name, tgts := range targetsByName {
				if len(tgts) < 2 {
					continue
				}
				for _, t := range tgts {
					if activeTargets[t.ID] {
						continue // has projects, skip
					}
					// Empty duplicate target
					if *doDelete {
						err := internal.DeleteTarget(ctx, client, token, orgID, t.ID)
						if err != nil {
							targetsFailed++
							log.Printf("  target %s (%s, %s): failed to delete: %v", t.ID, name, t.IntegrationType, err)
						} else {
							targetsDeleted++
							fmt.Printf("  target %s (%s, %s): deleted\n", t.ID, name, t.IntegrationType)
						}
					} else {
						fmt.Printf("  target %s (%s, %s): empty, would be deleted\n", t.ID, name, t.IntegrationType)
						targetsDeleted++ // count for dry-run summary
					}
				}
			}
		}
	}

	// Summary
	fmt.Println()
	if totalDuplicates == 0 && targetsDeleted == 0 {
		fmt.Println("No duplicates found.")
	} else if *doDelete {
		fmt.Printf("Summary: %d duplicate project(s) across %d org(s). %d deleted, %d failed.",
			totalDuplicates, len(orgsAffected), totalDeleted, totalFailed)
		if targetsDeleted > 0 || targetsFailed > 0 {
			fmt.Printf("\n         %d empty target(s) cleaned up, %d failed.",
				targetsDeleted, targetsFailed)
		}
	} else {
		fmt.Printf("Summary: %d duplicate project(s) across %d org(s).",
			totalDuplicates, len(orgsAffected))
		if targetsDeleted > 0 {
			fmt.Printf("\n         %d empty duplicate target(s) would be removed.", targetsDeleted)
		}
		fmt.Printf("\nRun with --delete to remove them.")
	}
	if failedOrgs > 0 {
		fmt.Printf(" (%d org(s) failed to scan)", failedOrgs)
	}
	fmt.Println()
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
