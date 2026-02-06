package internal

import (
	"fmt"
	"strings"
)

// Target represents a Snyk import target.
type Target struct {
	Name       string `json:"name,omitempty"`
	Owner      string `json:"owner,omitempty"`
	Branch     string `json:"branch,omitempty"`
	ProjectKey string `json:"projectKey,omitempty"`
	RepoSlug   string `json:"repoSlug,omitempty"`
}

// ImportTarget is a target with its org and integration context.
type ImportTarget struct {
	Target        Target `json:"target"`
	OrgID         string `json:"orgId"`
	IntegrationID string `json:"integrationId"`
}

// SCM origin values that the refresh tool supports.
// GitLab is excluded because the Snyk API doesn't provide the numeric
// project ID required by the import API.
var scmOrigins = map[string]bool{
	"github":                true,
	"github-cloud-app":      true,
	"github-enterprise":     true,
	"bitbucket-cloud":       true,
	"bitbucket-connect-app": true,
	"bitbucket-cloud-app":   true,
	"azure-repos":           true,
	"bitbucket-server":      true,
}

// IsSCMOrigin returns true if the origin is a supported SCM type.
func IsSCMOrigin(origin string) bool {
	return scmOrigins[origin]
}

// OriginToIntegrationKey maps a project origin to the integration key
// used by ListIntegrations. Most are 1:1, except bitbucket-connect-app
// which maps to bitbucket-cloud.
func OriginToIntegrationKey(origin string) string {
	if origin == "bitbucket-connect-app" {
		return "bitbucket-cloud"
	}
	return origin
}

// ProjectToTarget converts a Snyk project into an import Target.
// Returns (target, true) on success, or (Target{}, false) if the
// origin is unsupported (e.g. GitLab).
func ProjectToTarget(name, origin, branch string) (Target, bool) {
	switch origin {
	case "github", "github-cloud-app", "github-enterprise",
		"bitbucket-cloud", "bitbucket-connect-app", "bitbucket-cloud-app",
		"azure-repos":
		// Name format: "owner/repo:path/to/manifest"
		base := strings.SplitN(name, ":", 2)[0]
		parts := strings.SplitN(base, "/", 2)
		if len(parts) < 2 {
			return Target{}, false
		}
		// Remove any trailing parenthetical like "(branch)"
		repoName := strings.SplitN(parts[1], "(", 2)[0]
		t := Target{
			Owner: parts[0],
			Name:  repoName,
		}
		if branch != "" {
			t.Branch = branch
		}
		return t, true

	case "bitbucket-server":
		// Name format: "projectKey/repoSlug:path"
		base := strings.SplitN(name, ":", 2)[0]
		parts := strings.SplitN(base, "/", 2)
		if len(parts) < 2 {
			return Target{}, false
		}
		repoSlug := strings.SplitN(parts[1], "(", 2)[0]
		return Target{
			ProjectKey: parts[0],
			RepoSlug:   repoSlug,
		}, true

	default:
		// Unsupported origin (e.g. gitlab, cli, docker-hub)
		return Target{}, false
	}
}

// TargetID generates a deduplication key for a target, matching the
// TypeScript generateTargetId logic.
func TargetID(orgID, integrationID string, t Target) string {
	// Collect non-empty target properties in a stable order matching targetProps
	var parts []string
	if t.Name != "" {
		parts = append(parts, t.Name)
	}
	if t.ProjectKey != "" {
		parts = append(parts, t.ProjectKey)
	}
	if t.RepoSlug != "" {
		parts = append(parts, t.RepoSlug)
	}
	if t.Owner != "" {
		parts = append(parts, t.Owner)
	}
	if t.Branch != "" {
		parts = append(parts, t.Branch)
	}
	return fmt.Sprintf("%s:%s:%s", orgID, integrationID, strings.Join(parts, ":"))
}
