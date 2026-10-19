# IAM Roles for Service Accounts (IRSA) for the `callbacks` namespace.
#
# The External Secrets controller, acting as the callbacks/callbacks-secrets-reader service
# account, may read this namespace's secrets and nothing else. The app pods run as a different
# account with no AWS access, and Kyverno stops any pod from running as the reader account
# (k8s/kyverno-policies.yaml).

resource "aws_iam_openid_connect_provider" "eks" {
  url            = aws_eks_cluster.platform.identity[0].oidc[0].issuer
  client_id_list = ["sts.amazonaws.com"]
}

locals {
  eks_oidc_host = trimprefix(aws_eks_cluster.platform.identity[0].oidc[0].issuer, "https://")
}

data "aws_iam_policy_document" "callbacks_secrets_reader_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.eks_oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.eks_oidc_host}:sub"
      values   = ["system:serviceaccount:callbacks:callbacks-secrets-reader"]
    }
  }
}

resource "aws_iam_role" "callbacks_secrets_reader" {
  name               = "callbacks-secrets-reader"
  assume_role_policy = data.aws_iam_policy_document.callbacks_secrets_reader_trust.json
}

data "aws_iam_policy_document" "callbacks_secrets_reader" {
  statement {
    actions   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
    resources = ["arn:aws:secretsmanager:${var.region}:${data.aws_caller_identity.current.account_id}:secret:prod/callbacks/*"]
  }
}

resource "aws_iam_role_policy" "callbacks_secrets_reader" {
  name   = "read-callbacks-secrets"
  role   = aws_iam_role.callbacks_secrets_reader.id
  policy = data.aws_iam_policy_document.callbacks_secrets_reader.json
}
