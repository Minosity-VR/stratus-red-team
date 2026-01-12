package kubernetes

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/datadog/stratus-red-team/v2/internal/utils/kubernetes"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const techniqueID = "k8s.credential-access.steal-cloud-credentials"

// Cloud credential paths to check
var cloudCredentialPaths = []string{
	// AWS
	"$HOME/.aws",
	"$HOME/.aws/credentials",
	"$HOME/.aws/config",
	// Azure
	"$HOME/.azure",
	"$HOME/.azure/credentials",
	// GCP
	"$HOME/.config/gcloud",
	"$HOME/.config/gcloud/credentials.db",
	"$HOME/.config/gcloud/application_default_credentials.json",
	// Kubernetes
	"$HOME/.kube",
	"$HOME/.kube/config",
	"/var/run/secrets/kubernetes.io/serviceaccount/token",
	"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
	// Docker
	"$HOME/.docker",
	"$HOME/.docker/config.json",
	// SSH
	"$HOME/.ssh",
	"$HOME/.ssh/id_rsa",
	"$HOME/.ssh/id_ed25519",
	// Other
	"/etc/shadow",
	"/etc/passwd",
}

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 techniqueID,
		FriendlyName:       "Steal Cloud Credentials from Pod",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.CredentialAccess},
		Description: `
Attempts to read cloud provider credentials and sensitive files from within a pod.
This simulates an attacker extracting credentials after gaining access to a container.

Warm-up:

- Create the Stratus Red Team namespace
- Create a Pod

Detonation:

- Execute commands in the pod to read common cloud credential paths: AWS, Azure, GCP, Kubernetes, Docker, SSH
- Files are read with cat and output is discarded (cat file > /dev/null)
`,
		Detection: `
Monitor for:
- File read access to well-known credential paths (in ~/.aws, ~/.azure, ~/.config/gcloud, ~/.kube, ...)
- Processes reading /var/run/secrets/kubernetes.io/serviceaccount/* (beware of false positives, this file is often used by the application itself)
`,
		PrerequisitesTerraformCode: tf,
		PodConfigViaTerraform:      true,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	config := providers.K8s().GetRestConfig()
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	podName := params["pod_name"]

	log.Println("Attempting to read cloud credentials in pod " + podName)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build a shell script to read all credential files (cat to /dev/null to trigger read access)
	var readCommands []string
	for _, path := range cloudCredentialPaths {
		// Output is discarded to avoid actual leak in logs
		readCommands = append(readCommands, fmt.Sprintf(`cat %s > /dev/null 2>&1 && echo "READ: %s" || echo "FAILED: %s"`, path, path, path))
	}
	script := strings.Join(readCommands, "; ")

	stdout, stderr, err := kubernetes.ExecInPod(ctx, config, client, namespace, podName, "", []string{"sh", "-c", script})
	if err != nil {
		return fmt.Errorf("failed to read cloud credentials: %w (stderr: %s)", err, stderr)
	}

	log.Println("Cloud credentials read results:")
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, "READ:") {
			log.Println("[+] " + line)
		}
	}

	return nil
}
