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

const techniqueID = "k8s.discovery.ip-grabber"

type IPGrabber string

const (
	IPInfo       IPGrabber = "ipinfo.io"
	IfconfigMe   IPGrabber = "ifconfig.me"
	ICanHazIP    IPGrabber = "icanhazip.com"
	CheckIP      IPGrabber = "checkip.amazonaws.com"
	IPEchoNet    IPGrabber = "ipecho.net"
	WhatIsMyIPMe IPGrabber = "whatismyip.akamai.com"
)

var ipGrabberURLs = map[IPGrabber]string{
	IPInfo:       "https://ipinfo.io/ip",
	IfconfigMe:   "https://ifconfig.me/ip",
	ICanHazIP:    "https://icanhazip.com",
	CheckIP:      "https://checkip.amazonaws.com",
	IPEchoNet:    "https://ipecho.net/plain",
	WhatIsMyIPMe: "http://whatismyip.akamai.com",
}

type Method string

const (
	Curl   Method = "curl"
	Wget   Method = "wget"
	NodeJS Method = "node"
	Python Method = "python"
)

type MethodConfig struct {
	containerImage string
	buildCommand   func(url string) []string
}

var methodConfigs = map[Method]MethodConfig{
	Curl: {
		containerImage: "public.ecr.aws/docker/library/alpine:3.15.0",
		buildCommand:   func(url string) []string { return []string{"curl", "-s", url} },
	},
	Wget: {
		containerImage: "public.ecr.aws/docker/library/alpine:3.15.0",
		buildCommand:   func(url string) []string { return []string{"wget", "-qO-", url} },
	},
	NodeJS: {
		containerImage: "node:20-alpine",
		buildCommand: func(url string) []string {
			script := fmt.Sprintf(`require('https').get('%s', r => { r.on('data', d => process.stdout.write(d)); });`, url)
			return []string{"node", "-e", script}
		},
	},
	Python: {
		containerImage: "python:3.12-alpine",
		buildCommand: func(url string) []string {
			script := fmt.Sprintf(`import urllib.request; print(urllib.request.urlopen('%s').read().decode())`, url)
			return []string{"python3", "-c", script}
		},
	},
}

func supportedIPGrabbers() string {
	var grabbers []string
	for grabber := range ipGrabberURLs {
		grabbers = append(grabbers, string(grabber))
	}
	sort.Strings(grabbers)
	return strings.Join(grabbers, ", ")
}

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 techniqueID,
		FriendlyName:       "Contact IP Grabber Website from Pod",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Discovery},
		Description: `
Contacts an external IP grabber website from within a pod to discover the external IP address.
This is a used by attackers to determine the network egress point when they don't want to expose
their infrastructure.

Warm-up:

- Create the Stratus Red Team namespace
- Create a Pod

Detonation:

- Execute a command in the pod to contact an IP grabber website
- Supported IP grabbers: ` + supportedIPGrabbers() + `
`,
		Detection: `
Monitor for outbound connections to known IP grabber services. Common indicators:
- DNS queries or HTTP requests to well-known websites
- Processes spawning curl/wget to these domains
`,
		PrerequisitesTerraformCode: tf,
		PodConfigViaTerraform:      true,
		Detonate:                   detonate,
	})
}

// TODO: Implement TTP variation
func detonate(params map[string]string, providers stratus.CloudProviders) error {
	return detonateWithOptions(params, providers, IPInfo, Curl)
}

func detonateWithOptions(params map[string]string, providers stratus.CloudProviders, grabber IPGrabber, method Method) error {
	config := providers.K8s().GetRestConfig()
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	podName := params["pod_name"]

	url, ok := ipGrabberURLs[grabber]
	if !ok {
		return fmt.Errorf("unknown IP grabber: %s", grabber)
	}

	methodConfig, ok := methodConfigs[method]
	if !ok {
		return fmt.Errorf("unknown method: %s", method)
	}

	cmd := methodConfig.buildCommand(url)

	log.Printf("Contacting IP grabber %s using %s (requires image: %s)", grabber, method, methodConfig.containerImage)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stdout, stderr, err := kubernetes.ExecInPod(ctx, config, client, namespace, podName, "", cmd)
	if err != nil {
		return fmt.Errorf("failed to contact IP grabber: %w (stderr: %s)", err, stderr)
	}

	log.Printf("External IP address: %s", stdout)
	return nil
}
