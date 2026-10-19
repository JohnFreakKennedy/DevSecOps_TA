# Replaces `aws_s3_bucket.audit`. The bucket had no versioning, no immutability, no retention
# rule, no TLS-only policy, and it sat in the prod account. That is the account an attacker with
# the old CI policy (Action "*") controlled, so they could delete the evidence.
#
# The new bucket lives in the log-archive account. Prod writes to it only through the
# organisation CloudTrail and the log streams in log-shipping.tf. Object Lock in COMPLIANCE mode:
# nobody, including the log-archive root user, can delete a stored object version or shorten its
# retention. The bucket's default retention, its policy and its key are protected by the SCP in
# org-guardrails.tf. Consequences: SUBMISSION.md §2.2 step 7.

locals {
  org_trail_name = "org-trail"
  org_trail_arn  = "arn:aws:cloudtrail:${var.region}:${var.management_account_id}:trail/${local.org_trail_name}"
}

resource "aws_s3_bucket" "audit" {
  provider = aws.log_archive

  bucket              = var.audit_bucket_name
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "audit" {
  provider = aws.log_archive
  bucket   = aws_s3_bucket.audit.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  provider = aws.log_archive
  bucket   = aws_s3_bucket.audit.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.audit_log_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit]
}

resource "aws_s3_bucket_public_access_block" "audit" {
  provider = aws.log_archive
  bucket   = aws_s3_bucket.audit.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit" {
  provider = aws.log_archive
  bucket   = aws_s3_bucket.audit.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  provider = aws.log_archive
  bucket   = aws_s3_bucket.audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  provider = aws.log_archive
  bucket   = aws_s3_bucket.audit.id

  rule {
    id     = "archive-then-expire"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = var.audit_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "audit_bucket" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.org_trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/AWSLogs/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.org_trail_arn]
    }
  }

  statement {
    sid       = "TlsOnly"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  provider = aws.log_archive
  bucket   = aws_s3_bucket.audit.id
  policy   = data.aws_iam_policy_document.audit_bucket.json
}

# Only Security and incident responders can decrypt. Account admins in the log-archive account
# can manage the key but not read logs. They get no kms:CreateGrant either, because a grant
# could hand them Decrypt. Rewriting the key policy is the remaining path; it shows up in
# CloudTrail and alerts.
data "aws_iam_policy_document" "audit_key" {
  statement {
    sid = "KeyAdministrationWithoutDecrypt"
    actions = [
      "kms:CancelKeyDeletion", "kms:CreateAlias", "kms:Delete*", "kms:Describe*", "kms:Disable*",
      "kms:Enable*", "kms:Get*", "kms:List*", "kms:Put*", "kms:Revoke*",
      "kms:ScheduleKeyDeletion", "kms:TagResource", "kms:UntagResource", "kms:Update*",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.log_archive_account_id}:root"]
    }
  }

  statement {
    sid       = "CloudTrailEncrypt"
    actions   = ["kms:DescribeKey", "kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.org_trail_arn]
    }
  }

  statement {
    sid       = "SecurityDecrypt"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = var.audit_log_reader_role_arns
    }
  }
}

resource "aws_kms_key" "audit" {
  provider = aws.log_archive

  description             = "Audit logs: only Security can decrypt"
  enable_key_rotation     = true
  deletion_window_in_days = 30 # a scheduled deletion alerts and can be cancelled for 30 days
  policy                  = data.aws_iam_policy_document.audit_key.json
}

# One trail for every account in the organisation, all regions, with digest files so tampering
# is detectable (`aws cloudtrail validate-logs`).
resource "aws_cloudtrail" "org" {
  provider = aws.management

  name                          = local.org_trail_name
  s3_bucket_name                = aws_s3_bucket.audit.id
  kms_key_id                    = aws_kms_key.audit.arn
  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  # Object-level events only where reading an object is itself a security event. Not for this
  # bucket: logging the trail's own writes would loop.
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = [for arn in var.sensitive_data_bucket_arns : "${arn}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.audit]
}
