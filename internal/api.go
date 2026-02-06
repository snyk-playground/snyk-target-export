package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Org represents a Snyk organization.
type Org struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// Project represents a Snyk project with the fields we need for refresh.
type Project struct {
	ID              string
	Name            string
	Origin          string
	Branch          string
	TargetReference string
	Created         string // ISO 8601 timestamp from Snyk API
	TargetID        string // Snyk target ID from relationships
}

// FetchOrgs fetches all organizations in a Snyk group, handling pagination.
func FetchOrgs(ctx context.Context, client *http.Client, token, groupID string) ([]Org, error) {
	baseURL := GetSnykAPIBaseURL()
	var allOrgs []Org
	page := 1
	perPage := 100

	for {
		apiURL := fmt.Sprintf("%s/v1/group/%s/orgs?perPage=%d&page=%d",
			baseURL, url.PathEscape(groupID), perPage, page)

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Authorization", "token "+token)
		req.Header.Set("Accept", "application/json")

		resp, body, err := DoWithRetry(ctx, client, req)
		if err != nil {
			return nil, fmt.Errorf("fetch orgs page %d: %w", page, err)
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("fetch orgs: status %d, body: %s", resp.StatusCode, string(body))
		}

		var response struct {
			Orgs []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Slug string `json:"slug"`
			} `json:"orgs"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("decode orgs response: %w", err)
		}

		for _, o := range response.Orgs {
			allOrgs = append(allOrgs, Org{
				ID:   o.ID,
				Name: o.Name,
				Slug: o.Slug,
			})
		}

		// If we got fewer than perPage results, we've reached the last page
		if len(response.Orgs) < perPage {
			break
		}
		page++
	}

	return allOrgs, nil
}

// ListIntegrations lists integrations for a Snyk org.
// Returns a map of integration type name to integration ID.
func ListIntegrations(ctx context.Context, client *http.Client, token, orgID string) (map[string]string, error) {
	baseURL := GetSnykAPIBaseURL()
	apiURL := fmt.Sprintf("%s/v1/org/%s/integrations", baseURL, url.PathEscape(orgID))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/json")

	resp, body, err := DoWithRetry(ctx, client, req)
	if err != nil {
		return nil, fmt.Errorf("list integrations: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("list integrations: status %d, body: %s", resp.StatusCode, string(body))
	}

	var data map[string]string
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("decode integrations: %w", err)
	}
	return data, nil
}

// FetchProjects fetches all projects for a Snyk org via the REST API,
// including the origin and targetReference fields needed for refresh.
func FetchProjects(ctx context.Context, client *http.Client, token, orgID string) ([]Project, error) {
	baseURL := GetSnykAPIBaseURL()
	firstURL := fmt.Sprintf("%s/rest/orgs/%s/projects?version=2025-09-28&limit=100",
		baseURL, url.PathEscape(orgID))
	var projects []Project
	nextURL := firstURL

	// Extract host for SSRF-safe pagination
	apiHost := "api.snyk.io"
	if parsed, err := url.Parse(baseURL); err == nil && parsed.Host != "" {
		apiHost = parsed.Host
	}

	for nextURL != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", nextURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Authorization", "token "+token)
		req.Header.Set("Accept", "application/vnd.api+json")

		resp, body, err := DoWithRetry(ctx, client, req)
		if err != nil {
			return nil, fmt.Errorf("fetch projects: %w", err)
		}
		if resp.StatusCode == 404 {
			// Org not found or no projects
			return projects, nil
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("fetch projects: status %d, body: %s", resp.StatusCode, string(body))
		}

		var result struct {
			Data []struct {
				ID            string                 `json:"id"`
				Attributes    map[string]interface{} `json:"attributes"`
				Relationships map[string]interface{} `json:"relationships"`
			} `json:"data"`
			Links map[string]interface{} `json:"links"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("decode projects: %w", err)
		}

		for _, p := range result.Data {
			attrs := p.Attributes
			name, _ := attrs["name"].(string)
			origin, _ := attrs["origin"].(string)
			created, _ := attrs["created"].(string)

			// Extract branch: prefer targetReference, fall back to branch
			targetRef, _ := attrs["targetReference"].(string)
			if targetRef == "" {
				targetRef, _ = attrs["target_reference"].(string)
			}
			branch, _ := attrs["branch"].(string)
			if branch == "" {
				branch = targetRef
			}

			// Extract target ID from relationships
			var targetID string
			if rels := p.Relationships; rels != nil {
				if targetRel, ok := rels["target"].(map[string]interface{}); ok {
					if targetData, ok := targetRel["data"].(map[string]interface{}); ok {
						targetID, _ = targetData["id"].(string)
					}
				}
			}

			projects = append(projects, Project{
				ID:              p.ID,
				Name:            name,
				Origin:          origin,
				Branch:          branch,
				TargetReference: targetRef,
				Created:         created,
				TargetID:        targetID,
			})
		}

		// Pagination: follow links.next with SSRF validation
		nextURL = ""
		if result.Links != nil {
			if nextRaw, ok := result.Links["next"]; ok {
				if nextStr, ok := nextRaw.(string); ok && nextStr != "" {
					if isAllowedNextURL(nextStr, apiHost) {
						if strings.HasPrefix(nextStr, "/") {
							nextURL = baseURL + nextStr
						} else {
							nextURL = nextStr
						}
					}
				}
			}
		}
	}

	return projects, nil
}

// APITarget represents a Snyk target (repo-level entry) from the REST API.
// This is distinct from Target which represents an import target.
type APITarget struct {
	ID              string
	DisplayName     string
	IntegrationID   string
	IntegrationType string
	CreatedAt       string
}

// FetchTargets fetches all targets for a Snyk org via the REST API,
// including empty targets (no projects). This is needed to find orphaned
// targets left behind after project deletion.
func FetchTargets(ctx context.Context, client *http.Client, token, orgID string) ([]APITarget, error) {
	baseURL := GetSnykAPIBaseURL()
	firstURL := fmt.Sprintf("%s/rest/orgs/%s/targets?version=2025-09-28&limit=100&exclude_empty=false",
		baseURL, url.PathEscape(orgID))
	var targets []APITarget
	nextURL := firstURL

	apiHost := "api.snyk.io"
	if parsed, err := url.Parse(baseURL); err == nil && parsed.Host != "" {
		apiHost = parsed.Host
	}

	for nextURL != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", nextURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Authorization", "token "+token)
		req.Header.Set("Accept", "application/vnd.api+json")

		resp, body, err := DoWithRetry(ctx, client, req)
		if err != nil {
			return nil, fmt.Errorf("fetch targets: %w", err)
		}
		if resp.StatusCode == 404 {
			return targets, nil
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("fetch targets: status %d, body: %s", resp.StatusCode, string(body))
		}

		var result struct {
			Data []struct {
				ID            string                 `json:"id"`
				Attributes    map[string]interface{} `json:"attributes"`
				Relationships map[string]interface{} `json:"relationships"`
			} `json:"data"`
			Links map[string]interface{} `json:"links"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("decode targets: %w", err)
		}

		for _, t := range result.Data {
			attrs := t.Attributes
			displayName, _ := attrs["display_name"].(string)
			createdAt, _ := attrs["created_at"].(string)

			var integrationID, integrationType string
			if rels := t.Relationships; rels != nil {
				if intRel, ok := rels["integration"].(map[string]interface{}); ok {
					if intData, ok := intRel["data"].(map[string]interface{}); ok {
						integrationID, _ = intData["id"].(string)
						if intAttrs, ok := intData["attributes"].(map[string]interface{}); ok {
							integrationType, _ = intAttrs["integration_type"].(string)
						}
					}
				}
			}

			targets = append(targets, APITarget{
				ID:              t.ID,
				DisplayName:     displayName,
				IntegrationID:   integrationID,
				IntegrationType: integrationType,
				CreatedAt:       createdAt,
			})
		}

		nextURL = ""
		if result.Links != nil {
			if nextRaw, ok := result.Links["next"]; ok {
				if nextStr, ok := nextRaw.(string); ok && nextStr != "" {
					if isAllowedNextURL(nextStr, apiHost) {
						if strings.HasPrefix(nextStr, "/") {
							nextURL = baseURL + nextStr
						} else {
							nextURL = nextStr
						}
					}
				}
			}
		}
	}

	return targets, nil
}

// DeleteProject deletes a single project from a Snyk org via the REST API.
func DeleteProject(ctx context.Context, client *http.Client, token, orgID, projectID string) error {
	baseURL := GetSnykAPIBaseURL()
	apiURL := fmt.Sprintf("%s/rest/orgs/%s/projects/%s?version=2025-09-28",
		baseURL, url.PathEscape(orgID), url.PathEscape(projectID))

	req, err := http.NewRequestWithContext(ctx, "DELETE", apiURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.api+json")

	resp, body, err := DoWithRetry(ctx, client, req)
	if err != nil {
		return fmt.Errorf("delete project: %w", err)
	}
	// 204 No Content is the expected success response
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("delete project: status %d, body: %s", resp.StatusCode, string(body))
	}
	return nil
}

// DeleteTarget deletes a target from a Snyk org via the REST API.
// This removes the repository-level entry. It will fail if the target
// still has projects attached.
func DeleteTarget(ctx context.Context, client *http.Client, token, orgID, targetID string) error {
	baseURL := GetSnykAPIBaseURL()
	apiURL := fmt.Sprintf("%s/rest/orgs/%s/targets/%s?version=2025-09-28",
		baseURL, url.PathEscape(orgID), url.PathEscape(targetID))

	req, err := http.NewRequestWithContext(ctx, "DELETE", apiURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.api+json")

	resp, body, err := DoWithRetry(ctx, client, req)
	if err != nil {
		return fmt.Errorf("delete target: %w", err)
	}
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("delete target: status %d, body: %s", resp.StatusCode, string(body))
	}
	return nil
}

// isAllowedNextURL validates a pagination URL to prevent SSRF.
// Allows relative URLs (starting with /) and absolute URLs on the same host.
func isAllowedNextURL(nextURL, allowedHost string) bool {
	if nextURL == "" {
		return false
	}
	if strings.HasPrefix(nextURL, "/") {
		return true
	}
	u, err := url.Parse(nextURL)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	return host == allowedHost || strings.HasSuffix(host, "."+allowedHost)
}
