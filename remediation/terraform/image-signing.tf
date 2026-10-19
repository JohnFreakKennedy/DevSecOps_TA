# The key that marks an image digest as approved for production. Kyverno admits only images
# signed with it (k8s/kyverno-policies.yaml).
#
# Identity stack (applied by a human, not CI). The key policy names the deploy role as the only
# signer. Account admins can manage the key but not sign with it. Through IAM alone they cannot
# grant themselves signing either, because KMS honours IAM policies only for actions the key
# policy gives the account. The remaining path, rewriting the key policy, is denied to the CI
# apply role (ci-oidc.tf) and alerts for humans (Part 3 detections).

data "aws_iam_policy_document" "image_signing_key" {
  statement {
    sid = "KeyAdministrationWithoutSigning"
    actions = [
      "kms:CancelKeyDeletion", "kms:CreateAlias", "kms:Delete*", "kms:Describe*", "kms:Disable*",
      "kms:Enable*", "kms:Get*", "kms:List*", "kms:Put*", "kms:Revoke*",
      "kms:ScheduleKeyDeletion", "kms:TagResource", "kms:UntagResource", "kms:Update*",
    ]
    resources = ["*"] # in a key policy, "*" means this key

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "OnlyTheDeployRoleSigns"
    actions   = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.ci["deploy"].arn]
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "image_signing" {
  description              = "cosign key: marks an image digest as approved for production"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  policy                   = data.aws_iam_policy_document.image_signing_key.json
}

resource "aws_kms_alias" "image_signing" {
  name          = "alias/image-signing-prod"
  target_key_id = aws_kms_key.image_signing.key_id
}
