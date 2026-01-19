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

const techniqueID = "k8s.execution.dependency-install"

type PackageManager string

const (
	NPM  PackageManager = "npm"
	Yarn PackageManager = "yarn"
	Pip  PackageManager = "pip"
	Go   PackageManager = "go"
)

type PackageManagerConfig struct {
	containerImage string
	command        []string
}

// Package to install for each package manager (well-known, lightweight packages)
var packageManagerConfigs = map[PackageManager]PackageManagerConfig{
	NPM: {
		containerImage: "node:20-alpine",
		command:        []string{"npm", "install", "--no-save", "semver"},
	},
	Yarn: {
		containerImage: "node:20-alpine",
		command:        []string{"yarn", "add", "--no-lockfile", "semver"},
	},
	Pip: {
		containerImage: "python:3.12-alpine",
		command:        []string{"pip", "install", "--quiet", "semver"},
	},
	Go: {
		containerImage: "golang:1.22-alpine",
		command:        []string{"go", "install", "github.com/google/uuid@latest"},
	},
}

func supportedPackageManagers() string {
	var managers []string
	for pm := range packageManagerConfigs {
		managers = append(managers, string(pm))
	}
	sort.Strings(managers)
	return strings.Join(managers, ", ")
}

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 techniqueID,
		FriendlyName:       "Run Package Manager Install in Pod",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Execution},
		Description: `
Runs a package manager install command in a pod.

Warm-up:

- Create the Stratus Red Team namespace
- Create a Pod

Detonation:

- Execute a package manager install command in the pod
- Supported package managers: ` + supportedPackageManagers() + `
`,
		Detection: `
Monitor for:
- Execution of package manager binaries (npm, yarn, pip, conda, go, cargo...)

[!NOTE]
This is a false-positive prone detection that should be used with other detections rules for context
and corelation.
`,
		PrerequisitesTerraformCode: tf,
		PodConfigViaTerraform:      true,
		Detonate:                   detonate,
	})
}

// TODO: Implement TTP variation
func detonate(params map[string]string, providers stratus.CloudProviders) error {
	return detonateWithOptions(params, providers, NPM)
}

func detonateWithOptions(params map[string]string, providers stratus.CloudProviders, pm PackageManager) error {
	config := providers.K8s().GetRestConfig()
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	podName := params["pod_name"]

	pmConfig, ok := packageManagerConfigs[pm]
	if !ok {
		return fmt.Errorf("unknown package manager: %s", pm)
	}

	log.Printf("Running package manager: %s (requires image: %s)", pm, pmConfig.containerImage)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	stdout, stderr, err := kubernetes.ExecInPod(ctx, config, client, namespace, podName, "", pmConfig.command)
	if err != nil {
		return fmt.Errorf("failed to run package manager: %w (stderr: %s)", err, stderr)
	}

	if stdout != "" {
		log.Printf("Output: %s", stdout)
	}

	log.Printf("Successfully ran %s install", pm)
	return nil
}
