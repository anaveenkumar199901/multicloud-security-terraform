variable "deploy_aws" {
  type        = bool
  description = "Deploy AWS security baseline"
  default     = true
}

variable "deploy_gcp" {
  type        = bool
  description = "Deploy GCP security baseline"
  default     = true
}

variable "environment" {
  type        = string
  description = "Environment name like dev/sit/uat/prod"
  default     = "prod"

  validation {
    condition     = length(var.environment) >= 2 && length(var.environment) <= 12
    error_message = "environment must be 2-12 characters (e.g., dev/sit/uat/prod)."
  }
}

variable "default_tags" {
  type        = map(string)
  description = "Default tags (AWS only) applied via provider default_tags"
  default = {
    Project = "multicloud-security-baseline"
    Owner   = "Naveen Kumar"
  }
}

# ---------------- AWS ----------------
variable "aws_region" {
  type        = string
  description = "AWS region"
  default     = "ap-south-1"
}

variable "aws_security_email" {
  type        = string
  description = "Email to receive AWS security alerts (SNS). Optional."
  default     = ""
}

variable "cloudtrail_enable_data_events" {
  type        = bool
  description = "Enable CloudTrail S3 data events (can increase costs)"
  default     = false
}

# ---------------- GCP ----------------
variable "gcp_project_id" {
  type        = string
  description = "GCP project id (required if deploy_gcp=true)"
  default     = ""
}

variable "gcp_region" {
  type        = string
  description = "GCP region"
  default     = "asia-south1"
}

variable "gcp_security_email" {
  type        = string
  description = "Email to receive GCP security alerts (Monitoring notification channel). Optional."
  default     = ""
}

variable "gcp_log_bucket_location" {
  type        = string
  description = "GCS bucket location (multi-region like ASIA, US, EU or region). Prefer multi-region."
  default     = "ASIA"
}
