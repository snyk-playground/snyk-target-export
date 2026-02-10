package internal

import "testing"

func TestIsSCMOrigin(t *testing.T) {
	supported := []string{
		"github",
		"github-cloud-app",
		"github-enterprise",
		"bitbucket-cloud",
		"bitbucket-connect-app",
		"bitbucket-cloud-app",
		"azure-repos",
		"bitbucket-server",
	}
	for _, origin := range supported {
		if !IsSCMOrigin(origin) {
			t.Errorf("IsSCMOrigin(%q) = false, want true", origin)
		}
	}

	unsupported := []string{
		"gitlab",
		"cli",
		"docker-hub",
		"",
		"unknown",
	}
	for _, origin := range unsupported {
		if IsSCMOrigin(origin) {
			t.Errorf("IsSCMOrigin(%q) = true, want false", origin)
		}
	}
}

func TestOriginToIntegrationKey(t *testing.T) {
	tests := []struct {
		origin string
		want   string
	}{
		// bitbucket-cloud-app is the CLI alias; maps to bitbucket-connect-app
		{"bitbucket-cloud-app", "bitbucket-connect-app"},
		// bitbucket-connect-app is the real Snyk API key; identity mapping
		{"bitbucket-connect-app", "bitbucket-connect-app"},
		// bitbucket-cloud is a separate integration; identity mapping
		{"bitbucket-cloud", "bitbucket-cloud"},
		// All other origins pass through unchanged
		{"github", "github"},
		{"github-cloud-app", "github-cloud-app"},
		{"github-enterprise", "github-enterprise"},
		{"azure-repos", "azure-repos"},
		{"bitbucket-server", "bitbucket-server"},
		{"gitlab", "gitlab"},
	}
	for _, tt := range tests {
		got := OriginToIntegrationKey(tt.origin)
		if got != tt.want {
			t.Errorf("OriginToIntegrationKey(%q) = %q, want %q", tt.origin, got, tt.want)
		}
	}
}

func TestProjectToTarget_GitHub(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		branch string
		want   Target
		wantOK bool
	}{
		{
			name:   "myorg/myrepo:package.json",
			origin: "github",
			branch: "main",
			want:   Target{Owner: "myorg", Name: "myrepo", Branch: "main"},
			wantOK: true,
		},
		{
			name:   "myorg/myrepo:src/go.mod",
			origin: "github-cloud-app",
			branch: "",
			want:   Target{Owner: "myorg", Name: "myrepo"},
			wantOK: true,
		},
		{
			name:   "owner/repo(branch):Dockerfile",
			origin: "github",
			branch: "",
			want:   Target{Owner: "owner", Name: "repo"},
			wantOK: true,
		},
		{
			// No slash in name -> invalid
			name:   "noslash",
			origin: "github",
			branch: "",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		got, ok := ProjectToTarget(tt.name, tt.origin, tt.branch)
		if ok != tt.wantOK {
			t.Errorf("ProjectToTarget(%q, %q, %q) ok = %v, want %v", tt.name, tt.origin, tt.branch, ok, tt.wantOK)
			continue
		}
		if ok && got != tt.want {
			t.Errorf("ProjectToTarget(%q, %q, %q) = %+v, want %+v", tt.name, tt.origin, tt.branch, got, tt.want)
		}
	}
}

func TestProjectToTarget_BitbucketCloud(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		branch string
		want   Target
		wantOK bool
	}{
		{
			name:   "robhicksiii/Petclinic:pom.xml",
			origin: "bitbucket-connect-app",
			branch: "master",
			want:   Target{Owner: "robhicksiii", Name: "Petclinic", Branch: "master"},
			wantOK: true,
		},
		{
			name:   "robhicksiii/goof:package.json",
			origin: "bitbucket-cloud",
			branch: "main",
			want:   Target{Owner: "robhicksiii", Name: "goof", Branch: "main"},
			wantOK: true,
		},
		{
			name:   "workspace/repo:manifest",
			origin: "bitbucket-cloud-app",
			branch: "",
			want:   Target{Owner: "workspace", Name: "repo"},
			wantOK: true,
		},
	}
	for _, tt := range tests {
		got, ok := ProjectToTarget(tt.name, tt.origin, tt.branch)
		if ok != tt.wantOK {
			t.Errorf("ProjectToTarget(%q, %q, %q) ok = %v, want %v", tt.name, tt.origin, tt.branch, ok, tt.wantOK)
			continue
		}
		if ok && got != tt.want {
			t.Errorf("ProjectToTarget(%q, %q, %q) = %+v, want %+v", tt.name, tt.origin, tt.branch, got, tt.want)
		}
	}
}

func TestProjectToTarget_BitbucketServer(t *testing.T) {
	got, ok := ProjectToTarget("PROJ/my-repo:pom.xml", "bitbucket-server", "")
	if !ok {
		t.Fatal("ProjectToTarget for bitbucket-server returned false, want true")
	}
	want := Target{ProjectKey: "PROJ", RepoSlug: "my-repo"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}

	// Branch is ignored for bitbucket-server
	got2, ok2 := ProjectToTarget("KEY/slug:path", "bitbucket-server", "main")
	if !ok2 {
		t.Fatal("ProjectToTarget for bitbucket-server returned false, want true")
	}
	if got2.ProjectKey != "KEY" || got2.RepoSlug != "slug" {
		t.Errorf("got %+v, want ProjectKey=KEY, RepoSlug=slug", got2)
	}
}

func TestProjectToTarget_Unsupported(t *testing.T) {
	origins := []string{"gitlab", "cli", "docker-hub", ""}
	for _, origin := range origins {
		_, ok := ProjectToTarget("owner/repo:file", origin, "main")
		if ok {
			t.Errorf("ProjectToTarget with origin %q should return false", origin)
		}
	}
}

func TestProjectToTarget_AzureRepos(t *testing.T) {
	got, ok := ProjectToTarget("myorg/myproject:src/package.json", "azure-repos", "develop")
	if !ok {
		t.Fatal("ProjectToTarget for azure-repos returned false, want true")
	}
	want := Target{Owner: "myorg", Name: "myproject", Branch: "develop"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestTargetID(t *testing.T) {
	// GitHub-style target
	tid := TargetID("org-1", "int-1", Target{Name: "repo", Owner: "owner", Branch: "main"})
	if tid != "org-1:int-1:repo:owner:main" {
		t.Errorf("got %q", tid)
	}

	// Bitbucket-server style target
	tid2 := TargetID("org-2", "int-2", Target{ProjectKey: "PROJ", RepoSlug: "slug"})
	if tid2 != "org-2:int-2:PROJ:slug" {
		t.Errorf("got %q", tid2)
	}

	// Same target in different orgs should differ
	tidA := TargetID("org-a", "int-1", Target{Name: "repo", Owner: "owner"})
	tidB := TargetID("org-b", "int-1", Target{Name: "repo", Owner: "owner"})
	if tidA == tidB {
		t.Error("TargetIDs should differ for different orgs")
	}

	// Same target with different integrations should differ
	tidX := TargetID("org-1", "int-x", Target{Name: "repo", Owner: "owner"})
	tidY := TargetID("org-1", "int-y", Target{Name: "repo", Owner: "owner"})
	if tidX == tidY {
		t.Error("TargetIDs should differ for different integrations")
	}
}
