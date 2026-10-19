# Guardrails no role inside the prod account can switch off, including the CI apply role and
# account admins. Service control policies (SCPs) apply to every principal in the account except
# the listed break-glass and backup principals.
#
# Identity stack: applied from the management account by a human with just-in-time admin.

data "aws_iam_policy_document" "prod_guardrails" {
  statement {
    sid       = "NoLongLivedIamCredentials"
    effect    = "Deny"
    actions   = ["iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:CreateUser"]
    resources = ["*"]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = var.guardrail_exempt_principal_arns
    }
  }

  # A member account cannot change the organisation trail anyway. This statement also covers
  # account-level trails, AWS Config and GuardDuty.
  statement {
    sid    = "ProtectSecurityTelemetry"
    effect = "Deny"
    actions = [
      "cloudtrail:DeleteTrail",
      "cloudtrail:PutEventSelectors",
      "cloudtrail:StopLogging",
      "cloudtrail:UpdateTrail",
      "config:DeleteConfigurationRecorder",
      "config:DeleteDeliveryChannel",
      "config:StopConfigurationRecorder",
      "guardduty:DeleteDetector",
      "guardduty:DisassociateFromAdministratorAccount",
    ]
    resources = ["*"]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = var.guardrail_exempt_principal_arns
    }
  }

  # The audit evidence. Its objects are locked, but whoever controls the bucket policy, the
  # default retention, the lifecycle or the key could still stop new writes, shorten future
  # retention or make the logs unreadable.
  statement {
    sid    = "ProtectAuditBucketAndKey"
    effect = "Deny"
    actions = [
      "kms:DisableKey",
      "kms:PutKeyPolicy",
      "kms:ScheduleKeyDeletion",
      "s3:DeleteBucketPolicy",
      "s3:PutBucketObjectLockConfiguration",
      "s3:PutBucketPolicy",
      # Otherwise new log files could be encrypted with a key that someone else can read.
      "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration",
    ]
    resources = [aws_kms_key.audit.arn, aws_s3_bucket.audit.arn]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = var.guardrail_exempt_principal_arns
    }
  }

  statement {
    sid       = "StayInTheOrganisation"
    effect    = "Deny"
    actions   = ["organizations:LeaveOrganization"]
    resources = ["*"]
  }

  # Brief constraint: customer and financial data must not be copied into developer
  # environments. Sharing a snapshot with another account, or exporting one to S3, is how a
  # database copy usually leaves prod. Backups go to the backup account through AWS Backup,
  # run by an exempt role.
  statement {
    sid    = "NoSnapshotSharingOrExport"
    effect = "Deny"
    actions = [
      "ec2:ModifySnapshotAttribute",
      "rds:ModifyDBClusterSnapshotAttribute",
      "rds:ModifyDBSnapshotAttribute",
      "rds:StartExportTask",
    ]
    resources = ["*"]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = var.guardrail_exempt_principal_arns
    }
  }
}

resource "aws_organizations_policy" "prod_guardrails" {
  provider = aws.management

  name    = "prod-guardrails"
  type    = "SERVICE_CONTROL_POLICY"
  content = data.aws_iam_policy_document.prod_guardrails.json
}

# Attached to the prod OU and to the OU that holds the log-archive account.
resource "aws_organizations_policy_attachment" "prod_guardrails" {
  for_each = toset(var.guardrail_ou_ids)
  provider = aws.management

  policy_id = aws_organizations_policy.prod_guardrails.id
  target_id = each.value
}
