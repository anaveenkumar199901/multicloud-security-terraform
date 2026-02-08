# AWS outputs (safe if AWS skipped)
output "aws_logs_bucket_name" {
  value = try(module.aws_baseline[0].logs_bucket_name, null)
}

output "aws_kms_key_arn" {
  value = try(module.aws_baseline[0].kms_key_arn, null)
}

output "aws_sns_topic_arn" {
  value = try(module.aws_baseline[0].sns_topic_arn, null)
}

# GCP outputs (safe if GCP skipped)
output "gcp_log_bucket_name" {
  value = try(module.gcp_baseline[0].log_bucket_name, null)
}

output "gcp_kms_crypto_key_id" {
  value = try(module.gcp_baseline[0].kms_crypto_key_id, null)
}

output "gcp_logging_sink_name" {
  value = try(module.gcp_baseline[0].logging_sink_name, null)
}

output "gcp_alert_policy_name" {
  value = try(module.gcp_baseline[0].alert_policy_name, null)
}
