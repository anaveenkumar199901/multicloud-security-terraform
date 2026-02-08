# Example remote state for GCP (GCS)
# Copy to `backend.tf` and fill values, then run `terraform init -reconfigure`

terraform {
  backend "gcs" {
    bucket = "YOUR-TFSTATE-BUCKET"
    prefix = "multicloud-security/prod"
  }
}
