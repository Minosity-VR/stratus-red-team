terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.7.1"
    }
  }
}

variable "image" {
  description = "Container image to use for the pod."
  type        = string
  default     = "public.ecr.aws/docker/library/alpine:3.15.0"
}

variable "labels" {
  description = "JSON-encoded map of additional labels to apply to pods."
  type        = string
  default     = "{}"
}

variable "namespace" {
  description = "Kubernetes namespace to use. If empty, a new namespace will be created."
  type        = string
  default     = ""
}

variable "node_selector" {
  description = "JSON-encoded map of node selector labels."
  type        = string
  default     = "{}"
}

variable "tolerations" {
  description = "JSON-encoded list of tolerations for the pod."
  type        = string
  default     = "[]"
}

locals {
  kubeconfig_path = pathexpand("~/.kube/config")

  base_labels = {
    "datadoghq.com/stratus-red-team" : true
  }
  custom_labels = jsondecode(var.labels)
  labels        = merge(local.base_labels, local.custom_labels)

  create_namespace  = var.namespace == ""
  generated_ns_name = format("stratus-red-team-stealcreds-%s", random_string.suffix.result)
  namespace         = local.create_namespace ? local.generated_ns_name : var.namespace

  node_selector   = jsondecode(var.node_selector)
  resource_prefix = "stratus-red-team-stealcreds"
  tolerations     = jsondecode(var.tolerations)
}

provider "kubernetes" {
  config_path = fileexists(local.kubeconfig_path) ? local.kubeconfig_path : null
}

resource "random_string" "suffix" {
  length    = 8
  min_lower = 8
}

resource "kubernetes_namespace" "namespace" {
  count = local.create_namespace ? 1 : 0
  metadata {
    name   = local.generated_ns_name
    labels = local.base_labels
  }
}

resource "kubernetes_pod" "pod" {
  metadata {
    name      = format("%s-pod", local.resource_prefix)
    labels    = local.labels
    namespace = local.namespace
  }
  spec {
    node_selector = local.node_selector
    container {
      image   = var.image
      name    = "main-container"
      command = ["/bin/sh"]
      args = ["-c", <<-EOT
        # Create dummy cloud credential files for detection testing
        mkdir -p $HOME/.aws $HOME/.azure $HOME/.config/gcloud $HOME/.kube $HOME/.docker $HOME/.ssh
        echo '[default]' > $HOME/.aws/credentials
        echo 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE' >> $HOME/.aws/credentials
        echo 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' >> $HOME/.aws/credentials
        echo '[default]' > $HOME/.aws/config
        echo 'region = us-east-1' >> $HOME/.aws/config
        echo '{"subscriptionId": "00000000-0000-0000-0000-000000000000"}' > $HOME/.azure/credentials
        echo '{"client_id": "fake-client-id", "client_secret": "fake-secret"}' > $HOME/.config/gcloud/application_default_credentials.json
        echo 'apiVersion: v1' > $HOME/.kube/config
        echo 'clusters: []' >> $HOME/.kube/config
        echo '{"auths": {"https://index.docker.io/v1/": {"auth": "ZmFrZTpmYWtl"}}}' > $HOME/.docker/config.json
        echo '-----BEGIN OPENSSH PRIVATE KEY-----' > $HOME/.ssh/id_rsa
        echo 'fake-private-key-content-for-testing' >> $HOME/.ssh/id_rsa
        echo '-----END OPENSSH PRIVATE KEY-----' >> $HOME/.ssh/id_rsa
        echo '-----BEGIN OPENSSH PRIVATE KEY-----' > $HOME/.ssh/id_ed25519
        echo 'fake-ed25519-key-content-for-testing' >> $HOME/.ssh/id_ed25519
        echo '-----END OPENSSH PRIVATE KEY-----' >> $HOME/.ssh/id_ed25519
        # Keep container running
        while true; do sleep 3600; done
      EOT
      ]
    }
    dynamic "toleration" {
      for_each = local.tolerations
      content {
        key      = toleration.value.key
        operator = toleration.value.operator
        value    = toleration.value.value
        effect   = toleration.value.effect
      }
    }
  }
}

output "namespace" {
  value = local.namespace
}

output "pod_name" {
  value = kubernetes_pod.pod.metadata[0].name
}

output "display" {
  value = format("Pod %s in namespace %s ready", kubernetes_pod.pod.metadata[0].name, local.namespace)
}
