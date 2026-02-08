variable "name_prefix" {
  type        = string
  description = "Prefix for resource names"
}

variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "region" {
  type        = string
  description = "GCP region"
}

variable "log_bucket_location" {
  type        = string
  description = "GCS bucket location (multi-region like ASIA, US, EU or region)"
  default     = "ASIA"
}

variable "alert_email" {
  type        = string
  description = "Email for GCP security alerts (optional)"
  default     = ""
}
