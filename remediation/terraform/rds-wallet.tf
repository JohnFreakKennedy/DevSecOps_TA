# Replaces `aws_db_instance.wallet`. This is the end state; SUBMISSION.md §2.2 has the order.
#
# DO NOT flip storage_encrypted to true and apply. Encryption cannot be turned on for an existing
# instance, so Terraform plans destroy-and-recreate, and with the original
# `skip_final_snapshot = true` that deletes the wallet database without a snapshot. Encryption,
# the isolated subnet group and the TLS parameter group all arrive with a restore from an
# encrypted snapshot copy (§2.2 step 3).

resource "aws_kms_key" "wallet_db" {
  description             = "wallet-prod: storage, snapshots and the master-user secret"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_db_subnet_group" "wallet" {
  name       = "wallet-prod-isolated"
  subnet_ids = var.database_subnet_ids
}

resource "aws_security_group" "wallet_db" {
  name        = "wallet-db-prod"
  description = "wallet-prod Postgres: reachable only from the wallet and callback-handler pods"
  vpc_id      = var.vpc_id
  # No egress rules: Terraform removes the default allow-all rule, and RDS needs none.
}

resource "aws_vpc_security_group_ingress_rule" "wallet_db_clients" {
  for_each = toset(var.db_client_security_group_ids)

  security_group_id            = aws_security_group.wallet_db.id
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "Pods given this security group by a SecurityGroupPolicy"
}

resource "aws_db_parameter_group" "wallet" {
  name   = "wallet-prod-postgres16"
  family = "postgres16"

  # Refuse unencrypted client connections.
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  # Part 3: "unexpected connections to the wallet database". These lines record who connected,
  # from which address, and for how long.
  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  # Later hardening: pgaudit for DDL and role changes (needs shared_preload_libraries and a reboot).
}

resource "aws_db_instance" "wallet" {
  identifier = "wallet-prod"
  engine     = "postgres"
  # Assumed: the brief does not give a version. The parameter group family must match it.
  engine_version        = "16"
  instance_class        = var.wallet_db_instance_class
  storage_type          = "gp3"
  allocated_storage     = 100
  max_allocated_storage = 1000
  db_name               = "wallet"

  # RDS keeps the master password in Secrets Manager and rotates it. Applications never use the
  # master user: each service has its own database role with grants on its own tables only.
  username                      = "wallet_admin"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.wallet_db.arn
  # Turned on now so services can move off passwords later; using it is later hardening.
  iam_database_authentication_enabled = true

  # Was: publicly_accessible = true (step 2, in place)
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.wallet_db.id]
  # New with the restore (step 3): RDS cannot switch to another subnet group in the same VPC,
  # and a new parameter group would otherwise wait for a reboot.
  db_subnet_group_name = aws_db_subnet_group.wallet.name
  parameter_group_name = aws_db_parameter_group.wallet.name

  # Was: storage_encrypted = false (step 3, restore from an encrypted snapshot copy)
  storage_encrypted = true
  kms_key_id        = aws_kms_key.wallet_db.arn

  # Was: backup_retention_period = 1, skip_final_snapshot = true (step 1, in place)
  backup_retention_period   = 35
  delete_automated_backups  = false
  copy_tags_to_snapshot     = true
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "wallet-prod-final"

  multi_az                        = true
  auto_minor_version_upgrade      = true
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  # A second guard, inside Terraform: any plan that would destroy this database fails.
  lifecycle {
    prevent_destroy = true
  }

  depends_on = [aws_cloudwatch_log_group.wallet_db]
}
