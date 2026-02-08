output "logs_bucket_name" {
  value = aws_s3_bucket.logs.bucket
}

output "kms_key_arn" {
  value = aws_kms_key.log_kms.arn
}

output "sns_topic_arn" {
  value = aws_sns_topic.security_alerts.arn
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.this.id
}

output "securityhub_enabled" {
  value = true
}
