# Corrected excerpts for brief Part 2A. Shown as one module so `terraform validate` can check
# them together. In the real repository they are split into stacks (separate Terraform states):
#   - identity stack (ci-oidc.tf, eks-access.tf, image-signing.tf, org-guardrails.tf): applied
#     by a platform engineer with just-in-time admin access, never by CI, so CI cannot widen
#     its own permissions;
#   - log-archive stack (audit-logging.tf);
#   - prod workload stack (eks.tf, rds-wallet.tf, ecr.tf, log-shipping.tf, irsa-callbacks.tf):
#     applied by the CI apply role.

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      environment = "prod"
      managed-by  = "terraform"
    }
  }
}

# Audit logs live in a separate log-archive account. Nobody in the prod account administers it.
provider "aws" {
  alias  = "log_archive"
  region = var.region

  assume_role {
    role_arn = var.log_archive_terraform_role_arn
  }
}

# Service control policies and the organisation trail are managed from the management account.
provider "aws" {
  alias  = "management"
  region = var.region

  assume_role {
    role_arn = var.management_terraform_role_arn
  }
}
