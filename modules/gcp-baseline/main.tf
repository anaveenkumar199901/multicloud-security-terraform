# -----------------------
# Enable required APIs
# -----------------------
resource "google_project_service" "services" {
  for_each = toset([
    "logging.googleapis.com",
    "cloudkms.googleapis.com",
    "storage.googleapis.com",
    "monitoring.googleapis.com"
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# -----------------------
# KMS for log bucket encryption (CMEK)
# -----------------------
resource "google_kms_key_ring" "log_ring" {
  name     = "${var.name_prefix}-log-ring"
  location = var.region
  project  = var.project_id

  depends_on = [google_project_service.services]
}

resource "google_kms_crypto_key" "log_key" {
  name            = "${var.name_prefix}-log-key"
  key_ring        = google_kms_key_ring.log_ring.id
  rotation_period = "2592000s" # 30 days

  lifecycle {
    prevent_destroy = false
  }
}

# -----------------------
# Central log bucket (CMEK, uniform access)
# -----------------------
resource "google_storage_bucket" "log_bucket" {
  # Must be globally unique; tying to project ID makes it stable in most orgs
  name                        = "${var.name_prefix}-gcp-logs-${var.project_id}"
  project                     = var.project_id
  location                    = var.log_bucket_location
  uniform_bucket_level_access = true
  force_destroy               = false

  versioning { enabled = true }

  encryption {
    default_kms_key_name = google_kms_crypto_key.log_key.id
  }

  depends_on = [google_project_service.services]
}

# Storage service agent must use the CMEK key
data "google_project" "project" {
  project_id = var.project_id
}

resource "google_kms_crypto_key_iam_member" "storage_sa" {
  crypto_key_id = google_kms_crypto_key.log_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.project.number}@gs-project-accounts.iam.gserviceaccount.com"
}

# -----------------------
# Cloud Logging sink → export Cloud Audit Logs to GCS
# -----------------------
resource "google_logging_project_sink" "audit_to_bucket" {
  name        = "${var.name_prefix}-audit-logs-sink"
  project     = var.project_id
  destination = "storage.googleapis.com/${google_storage_bucket.log_bucket.name}"

  # Cloud Audit Logs across services
  filter = "logName:(\"cloudaudit.googleapis.com\")"
}

# Allow sink writer identity to write objects
resource "google_storage_bucket_iam_member" "sink_writer" {
  bucket = google_storage_bucket.log_bucket.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.audit_to_bucket.writer_identity
}

# -----------------------
# Detection: IAM policy change metric (SetIamPolicy)
# -----------------------
resource "google_logging_metric" "iam_policy_changes" {
  name        = "${var.name_prefix}-iam-policy-changes"
  project     = var.project_id
  description = "Counts IAM SetIamPolicy calls (policy changes)"

  # Cover common SetIamPolicy sources
  filter = join(" ", [
    "protoPayload.methodName=\"SetIamPolicy\"",
    "AND",
    "(",
    "protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\"",
    "OR",
    "protoPayload.serviceName=\"iam.googleapis.com\"",
    ")"
  ])

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "IAM Policy Changes"
  }
}

# -----------------------
# Alerting (optional): Email notification channel + alert policy
# -----------------------
resource "google_monitoring_notification_channel" "email" {
  count        = length(trimspace(var.alert_email)) > 0 ? 1 : 0
  project      = var.project_id
  display_name = "${var.name_prefix}-security-email"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }

  depends_on = [google_project_service.services]
}

resource "google_monitoring_alert_policy" "iam_policy_change_alert" {
  count        = length(trimspace(var.alert_email)) > 0 ? 1 : 0
  project      = var.project_id
  display_name = "${var.name_prefix}-ALERT-IAM-Policy-Change"
  combiner     = "OR"
  enabled      = true

  notification_channels = [google_monitoring_notification_channel.email[0].name]

  conditions {
    display_name = "IAM policy change detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.iam_policy_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_DELTA"
      }
    }
  }

  documentation {
    content   = "IAM policy change detected in project `${var.project_id}`. Review Cloud Audit Logs for details."
    mime_type = "text/markdown"
  }
}
