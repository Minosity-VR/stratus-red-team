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

const techniqueID = "k8s.discovery.dump-env-vars"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 techniqueID,
		FriendlyName:       "Dump Environment Variables from Pod",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Discovery, mitreattack.CredentialAccess},
		Description: `
Dumps all environment variables from within a pod.
Environment variables often contain sensitive information such as:
- API keys and secrets
- Database connection strings
- Cloud provider credentials
- Service account tokens
- Information about the application

Warm-up:

- Create the Stratus Red Team namespace
- Create a Pod

Detonation:

- Execute 'env' or 'printenv' command in the pod to dump all environment variables
`,
		Detection: `
Monitor for:
- Execution of 'env', 'printenv', or 'set' commands
- Processes reading /proc/*/environ
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

	log.Println("Dumping environment variables from pod " + podName)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stdout, stderr, err := kubernetes.ExecInPod(ctx, config, client, namespace, podName, "", []string{"env"})
	if err != nil {
		return fmt.Errorf("failed to dump environment variables: %w (stderr: %s)", err, stderr)
	}

	// Count and log the results
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	log.Printf("Found %d environment variables", len(lines))

	return nil
}
