variable "name_prefix" {
  type        = string
  description = "Prefix for resource names"
}

variable "cloudtrail_enable_data_events" {
  type        = bool
  description = "Enable CloudTrail S3 data events"
  default     = false
}

variable "sns_email_target" {
  type        = string
  description = "Email for AWS security alerts (SNS). If empty, SNS subscription is skipped."
  default     = ""
}
