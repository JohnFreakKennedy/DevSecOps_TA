variable "region" {
  type    = string
  default = "eu-central-1"
}

# --- Network -----------------------------------------------------------------------------

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  description = "Private subnets for EKS control-plane network interfaces and node groups. Egress through NAT only."
  type        = list(string)
}

variable "database_subnet_ids" {
  description = "Isolated subnets for RDS. No route to or from the internet."
  type        = list(string)
}

variable "db_client_security_group_ids" {
  description = "Security groups of the pods allowed to reach the wallet database: wallet and callback-handler, assigned by SecurityGroupPolicy objects (EKS security groups for pods)."
  type        = list(string)
}

# --- EKS ---------------------------------------------------------------------------------

variable "eks_cluster_role_arn" {
  type = string
}

variable "eks_version" {
  type = string
}

variable "eks_human_access" {
  description = <<-EOT
    Human access to the cluster through EKS access entries. Key = a label; principal_arn = an
    IAM Identity Center permission-set role or the break-glass role; policy_arn = an EKS access
    policy, e.g. AmazonEKSViewPolicy for engineers (with their team's namespaces), or
    AmazonEKSClusterAdminPolicy for the just-in-time PlatformAdmin role and the break-glass role.
    namespaces unset = the whole cluster.
  EOT
  type = map(object({
    principal_arn = string
    policy_arn    = string
    namespaces    = optional(list(string))
  }))
}

# --- GitLab CI ---------------------------------------------------------------------------

variable "gitlab_url" {
  description = "Issuer URL of the GitLab instance, e.g. https://gitlab.example.com"
  type        = string
}

variable "infra_project_path" {
  description = "GitLab project holding the Terraform code, e.g. platform/infrastructure"
  type        = string
}

variable "services" {
  description = "Deployable services: ECR repository name => GitLab project path."
  type        = map(string)
}

variable "ci_build_runner_egress_cidrs" {
  description = "Public egress (NAT) addresses of the build runners (tf-plan and build roles)."
  type        = list(string)
}

variable "ci_deploy_runner_egress_cidrs" {
  description = "Public egress (NAT) address of the protected prod-deploy runner (tf-apply and deploy roles)."
  type        = list(string)
}

variable "tf_state_bucket_arn" {
  type = string
}

# --- Wallet database ---------------------------------------------------------------------

variable "wallet_db_instance_class" {
  type    = string
  default = "db.r6g.large"
}

# --- Log archive and organisation --------------------------------------------------------

variable "log_archive_terraform_role_arn" {
  type = string
}

variable "management_terraform_role_arn" {
  type = string
}

variable "log_archive_account_id" {
  type = string
}

variable "management_account_id" {
  type = string
}

variable "audit_bucket_name" {
  type = string
}

variable "audit_log_retention_days" {
  description = "Set from the licence's record-keeping rules. Assumed 5 years until compliance confirms."
  type        = number
  default     = 1825
}

variable "audit_log_reader_role_arns" {
  description = "Roles allowed to decrypt audit logs: Security and the incident-response role."
  type        = list(string)
}

variable "log_archive_logs_destination_arn" {
  description = "CloudWatch Logs destination in the log-archive account that receives EKS and database logs."
  type        = string
}

variable "sensitive_data_bucket_arns" {
  description = "Buckets whose object reads and writes are logged as CloudTrail data events (KYC documents, exports)."
  type        = list(string)
}

variable "guardrail_ou_ids" {
  description = "AWS Organizations units that get the guardrail SCP: the one holding prod and the one holding the log-archive account."
  type        = list(string)
}

variable "guardrail_exempt_principal_arns" {
  description = "Principals exempt from the guardrail SCP: the break-glass users and role, the backup automation role, and the log-archive admin role used (by two people, with an alert) to change the audit bucket."
  type        = list(string)
}
