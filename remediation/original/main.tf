# Brief Part 2A, as given (Markdown escapes removed). Kept for before/after comparison only.

resource "aws_eks_cluster" "platform" {
  name     = "platform-prod"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    subnet_ids              = var.public_subnet_ids
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "ci" {
  name = "gitlab-ci"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_db_instance" "wallet" {
  identifier              = "wallet-prod"
  engine                  = "postgres"
  publicly_accessible     = true
  storage_encrypted       = false
  backup_retention_period = 1
  skip_final_snapshot     = true
}

resource "aws_s3_bucket" "audit" {
  bucket = "platform-audit-prod"
}
