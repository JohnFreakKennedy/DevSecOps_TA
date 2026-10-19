# Evidence copy. EKS control-plane logs and the wallet database logs stream to the log-archive
# account within minutes. Prod keeps a 90-day working copy for queries; deleting it does not
# touch the archived copy. A change to these subscription filters, or to the cluster's logging
# settings, alerts Security (Part 3 detections).

# RDS writes the exported Postgres log here. Created before the instance so retention is ours.
resource "aws_cloudwatch_log_group" "wallet_db" {
  name              = "/aws/rds/instance/wallet-prod/postgresql"
  retention_in_days = 90
}

resource "aws_cloudwatch_log_subscription_filter" "to_log_archive" {
  for_each = {
    eks       = aws_cloudwatch_log_group.eks.name
    wallet-db = aws_cloudwatch_log_group.wallet_db.name
  }

  name           = "to-log-archive"
  log_group_name = each.value
  filter_pattern = ""
  # A CloudWatch Logs destination in the log-archive account, which writes to the Object Lock
  # bucket through Amazon Data Firehose (not shown).
  destination_arn = var.log_archive_logs_destination_arn
}
