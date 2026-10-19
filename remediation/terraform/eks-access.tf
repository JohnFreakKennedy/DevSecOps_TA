# Who can talk to the platform-prod cluster, through EKS access entries.
#
# Identity stack (applied by a human, not CI). The CI apply role is denied these API calls
# (ci-oidc.tf), so the infrastructure pipeline cannot make itself a cluster admin.

# CI: the deploy role becomes the `ci-deployers` group, which k8s/rbac-ci-deployer.yaml binds to
# a Role that can only update Deployments in the service namespaces.
resource "aws_eks_access_entry" "ci_deploy" {
  cluster_name      = aws_eks_cluster.platform.name
  principal_arn     = aws_iam_role.ci["deploy"].arn
  kubernetes_groups = ["ci-deployers"]
}

# Humans: Identity Center permission-set roles and the break-glass role, mapped to EKS access
# policies. Engineers get view rights in their team's namespaces only.
resource "aws_eks_access_entry" "humans" {
  for_each = var.eks_human_access

  cluster_name  = aws_eks_cluster.platform.name
  principal_arn = each.value.principal_arn
}

resource "aws_eks_access_policy_association" "humans" {
  for_each = var.eks_human_access

  cluster_name  = aws_eks_cluster.platform.name
  principal_arn = aws_eks_access_entry.humans[each.key].principal_arn
  policy_arn    = each.value.policy_arn

  access_scope {
    type       = each.value.namespaces == null ? "cluster" : "namespace"
    namespaces = each.value.namespaces
  }
}
