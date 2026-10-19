# Replaces `aws_iam_policy.ci` (Action "*", Resource "*", used through a stored access key).
#
# GitLab jobs exchange their OIDC ID token for 1-hour credentials. There are four roles, one per
# job type. Each role trusts one token audience, and a job gets a token only for the audience its
# YAML declares. So code running inside the build job (for example a compromised npm package)
# cannot assume the deploy role, even though both jobs come from the same project and branch.
# Each role also works only from the network of the runners meant to use it.
#
# Identity stack: applied by a human with just-in-time admin, not by CI (see versions.tf).

locals {
  gitlab_host = trimprefix(var.gitlab_url, "https://")

  # GitLab puts the project and the ref into the token's `sub` claim:
  #   project_path:<group>/<project>:ref_type:branch:ref:<branch>
  infra_main_subs   = ["project_path:${var.infra_project_path}:ref_type:branch:ref:main"]
  service_main_subs = [for path in values(var.services) : "project_path:${path}:ref_type:branch:ref:main"]

  ci_roles = {
    # Terraform plan for prod, on main only. Merge-request plans run against staging.
    tf-plan = { subs = local.infra_main_subs, source_cidrs = var.ci_build_runner_egress_cidrs }
    # Terraform apply, after the GitLab environment approval, from the prod-deploy runner.
    tf-apply = { subs = local.infra_main_subs, source_cidrs = var.ci_deploy_runner_egress_cidrs }
    # Image build and scan. Shared by all services for launch; per-service roles come later.
    build = { subs = local.service_main_subs, source_cidrs = var.ci_build_runner_egress_cidrs }
    # Sign the approved digest and roll it out, from the prod-deploy runner.
    deploy = { subs = local.service_main_subs, source_cidrs = var.ci_deploy_runner_egress_cidrs }
  }

  ecr_push_actions = [
    "ecr:BatchCheckLayerAvailability",
    "ecr:BatchGetImage",
    "ecr:CompleteLayerUpload",
    "ecr:GetDownloadUrlForLayer",
    "ecr:InitiateLayerUpload",
    "ecr:PutImage",
    "ecr:UploadLayerPart",
  ]
}

resource "aws_iam_openid_connect_provider" "gitlab" {
  url            = var.gitlab_url
  client_id_list = [for name in keys(local.ci_roles) : "aws-prod-${name}"]
}

data "aws_iam_policy_document" "ci_trust" {
  for_each = local.ci_roles

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.gitlab.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.gitlab_host}:aud"
      values   = ["aws-prod-${each.key}"]
    }

    condition {
      test     = "StringLike"
      variable = "${local.gitlab_host}:sub"
      values   = each.value.subs
    }
  }
}

resource "aws_iam_role" "ci" {
  for_each = local.ci_roles

  name                 = "gitlab-${each.key}-prod"
  assume_role_policy   = data.aws_iam_policy_document.ci_trust[each.key].json
  max_session_duration = 3600
}

# --- Every CI role: credentials only work from its runners' network ------------------------
#
# A stolen session (Part 3: "CI-role access key observed from an unfamiliar source IP") fails
# anywhere else, and the apply and deploy sessions fail even on the build runners. Two limits:
#   - If runners reach AWS through VPC endpoints, aws:SourceIp is absent and this statement
#     denies everything. Use aws:SourceVpc instead.
#   - It does not protect the Kubernetes API. An EKS token is a presigned
#     sts:GetCallerIdentity call, which IAM policies cannot deny. The private EKS endpoint
#     (eks.tf) is what keeps stolen credentials away from the cluster.

data "aws_iam_policy_document" "ci_network_bound" {
  for_each = local.ci_roles

  statement {
    sid       = "DenyOutsideRunnerNetwork"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    condition {
      test     = "NotIpAddress"
      variable = "aws:SourceIp"
      values   = each.value.source_cidrs
    }

    # Calls that AWS services make on the role's behalf come from AWS, not from the runner.
    condition {
      test     = "Bool"
      variable = "aws:ViaAWSService"
      values   = ["false"]
    }
  }
}

resource "aws_iam_role_policy" "ci_network_bound" {
  for_each = aws_iam_role.ci

  name   = "deny-outside-runner-network"
  role   = each.value.id
  policy = data.aws_iam_policy_document.ci_network_bound[each.key].json
}

# --- tf-plan: read the infrastructure configuration ----------------------------------------

resource "aws_iam_role_policy_attachment" "tf_plan_read_only" {
  role       = aws_iam_role.ci["tf-plan"].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# ReadOnlyAccess can also read some data. Secrets, parameters and S3 objects are denied here.
# What remains readable (CloudWatch log events, DynamoDB items) is why only reviewed main code
# runs with this role. Plans run with `-lock=false` and read only the workload stack's state.
data "aws_iam_policy_document" "tf_plan_no_data_reads" {
  statement {
    sid       = "NoSecretReads"
    effect    = "Deny"
    actions   = ["secretsmanager:GetSecretValue", "ssm:GetParameter*"]
    resources = ["*"]
  }

  statement {
    sid           = "NoObjectReadsOutsideWorkloadState"
    effect        = "Deny"
    actions       = ["s3:GetObject", "s3:GetObjectVersion"]
    not_resources = ["${var.tf_state_bucket_arn}/prod/workload/*"]
  }
}

resource "aws_iam_role_policy" "tf_plan_no_data_reads" {
  name   = "deny-data-reads"
  role   = aws_iam_role.ci["tf-plan"].id
  policy = data.aws_iam_policy_document.tf_plan_no_data_reads.json
}

# --- tf-apply: admin inside the account, fenced in -------------------------------------------
#
# Terraform manages IAM, so a least-privilege apply role is mostly fiction. The risk is held by
# who can trigger it (protected main, environment approval, prod-deploy runner only), by the
# fence below, and by the organisation SCP (org-guardrails.tf). It can still change node
# configuration; such a change shows in the plan the approver reads.
# Later hardening: require a permissions boundary on every role it creates.

resource "aws_iam_role_policy_attachment" "tf_apply_admin" {
  role       = aws_iam_role.ci["tf-apply"].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# The fence keeps the infrastructure pipeline out of the trust chains that decide who controls
# production: the CI and break-glass identities, cluster access (eks-access.tf) and which images
# count as approved (image-signing.tf). Those live in the identity stack, applied by people.
data "aws_iam_policy_document" "tf_apply_fence" {
  statement {
    sid    = "CiCannotChangePrivilegedIdentities"
    effect = "Deny"
    actions = [
      "iam:Add*", "iam:Attach*", "iam:Create*", "iam:Delete*", "iam:Detach*",
      "iam:Put*", "iam:Remove*", "iam:Tag*", "iam:Untag*", "iam:Update*",
    ]
    resources = [
      "arn:aws:iam::*:oidc-provider/${local.gitlab_host}",
      "arn:aws:iam::*:role/aws-reserved/*", # IAM Identity Center roles (JIT PlatformAdmin and others)
      "arn:aws:iam::*:role/break-glass-*",
      "arn:aws:iam::*:role/gitlab-*",
      "arn:aws:iam::*:user/break-glass-*",
    ]
  }

  # Terraform here manages one account and needs no other role. Without this, the apply role
  # could rewrite another role's trust policy and become that role.
  statement {
    sid       = "CiCannotBecomeAnotherRole"
    effect    = "Deny"
    actions   = ["sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"]
    resources = ["*"]
  }

  statement {
    sid    = "CiCannotGrantItselfClusterAccess"
    effect = "Deny"
    actions = [
      "eks:AssociateAccessPolicy",
      "eks:CreateAccessEntry",
      "eks:DeleteAccessEntry",
      "eks:DisassociateAccessPolicy",
      "eks:UpdateAccessEntry",
    ]
    resources = ["*"]
  }

  # A shell on a node reaches every pod's secrets on that node.
  statement {
    sid       = "CiCannotRunCommandsOnNodes"
    effect    = "Deny"
    actions   = ["ssm:SendCommand", "ssm:StartSession"]
    resources = ["*"]
  }

  statement {
    sid    = "CiCannotSignOrRekeyImages"
    effect = "Deny"
    actions = [
      "kms:CreateGrant",
      "kms:DisableKey",
      "kms:PutKeyPolicy",
      "kms:ScheduleKeyDeletion",
      "kms:Sign",
    ]
    resources = [aws_kms_key.image_signing.arn]
  }
}

resource "aws_iam_role_policy" "tf_apply_fence" {
  name   = "fence"
  role   = aws_iam_role.ci["tf-apply"].id
  policy = data.aws_iam_policy_document.tf_apply_fence.json
}

# --- build: push images to the service repositories -------------------------------------------

data "aws_iam_policy_document" "build" {
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid       = "PushAndScanServiceImages"
    actions   = local.ecr_push_actions
    resources = [for repo in aws_ecr_repository.service : repo.arn]
  }
}

resource "aws_iam_role_policy" "build" {
  name   = "ecr-push"
  role   = aws_iam_role.ci["build"].id
  policy = data.aws_iam_policy_document.build.json
}

# --- deploy: sign the approved digest, then roll it out ---------------------------------------
#
# It can read service images but not push them, so it can only sign and deploy what a main
# build produced. Signatures go to their own repository. Kubernetes permissions come from the
# access entry in eks-access.tf: patch Deployments in service namespaces, nothing else.

data "aws_iam_policy_document" "deploy" {
  statement {
    sid       = "FindCluster"
    actions   = ["eks:DescribeCluster"]
    resources = [aws_eks_cluster.platform.arn]
  }

  statement {
    sid       = "SignApprovedImages"
    actions   = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"]
    resources = [aws_kms_key.image_signing.arn]
  }

  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid       = "ReadServiceImages"
    actions   = ["ecr:BatchGetImage", "ecr:DescribeImages", "ecr:GetDownloadUrlForLayer"]
    resources = [for repo in aws_ecr_repository.service : repo.arn]
  }

  statement {
    sid       = "WriteSignatures"
    actions   = local.ecr_push_actions
    resources = [aws_ecr_repository.signatures.arn]
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "deploy"
  role   = aws_iam_role.ci["deploy"].id
  policy = data.aws_iam_policy_document.deploy.json
}
