output "log_bucket_name" {
  value = google_storage_bucket.log_bucket.name
}

output "kms_crypto_key_id" {
  value = google_kms_crypto_key.log_key.id
}

output "logging_sink_name" {
  value = google_logging_project_sink.audit_to_bucket.name
}

output "alert_policy_name" {
  value = try(google_monitoring_alert_policy.iam_policy_change_alert[0].name, null)
}
