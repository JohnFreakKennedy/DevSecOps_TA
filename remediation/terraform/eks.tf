# Replaces the public, unlogged `platform-prod` cluster.
#
# Before: API endpoint open to 0.0.0.0/0, private endpoint off, cluster in public subnets.
# After:  private endpoint only. kubectl goes over NetBird (routing peer inside the VPC). CI
#         deploys from the protected runner inside the VPC.
#
# Order and operational consequences: SUBMISSION.md §2.2 (steps 5 and 6). In short: private
# endpoint first while the public one still admits only runner and NetBird addresses, then the
# public endpoint off. Changing subnet_ids updates in place with provider 6.69.1 (checked with a
# plan); older provider versions may force a new cluster, so read the plan.

resource "aws_eks_cluster" "platform" {
  name     = "platform-prod"
  role_arn = var.eks_cluster_role_arn
  version  = var.eks_version

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  access_config {
    # Access entries only; no aws-auth ConfigMap. EKS moves one step at a time:
    # CONFIG_MAP -> API_AND_CONFIG_MAP (migrate the mappings) -> API. Two applies.
    authentication_mode = "API"
    # Otherwise whoever created the cluster (the Terraform role) is a permanent cluster admin that
    # appears in no RBAC binding. Takes effect for new clusters only: changing it on an existing
    # cluster forces a new cluster (checked with a plan), so the lifecycle block below ignores
    # it. On platform-prod, delete the creator's access entry instead (SUBMISSION.md §2.2 step 6).
    bootstrap_cluster_creator_admin_permissions = false
  }

  # Needed to investigate Part 3: who read which secret and who created the pod.
  enabled_cluster_log_types = ["api", "audit", "authenticator"]

  # A customer-managed key, so decrypt calls show up in CloudTrail. An explicit key policy for it
  # is later hardening.
  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
  }

  lifecycle {
    ignore_changes = [access_config[0].bootstrap_cluster_creator_admin_permissions]
  }

  depends_on = [aws_cloudwatch_log_group.eks]
}

# Created before the cluster so retention is ours, not "never expire". log-shipping.tf streams
# these logs to the log-archive account.
resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/platform-prod/cluster"
  retention_in_days = 90
}

resource "aws_kms_key" "eks_secrets" {
  description         = "Envelope encryption for Kubernetes secrets in platform-prod"
  enable_key_rotation = true
}
