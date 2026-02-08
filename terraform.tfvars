# Toggle clouds
deploy_aws = true
deploy_gcp = true

environment = "prod"

# ---------------- AWS ----------------
aws_region         = "ap-south-1"
aws_security_email = "you@company.com"   # optional
cloudtrail_enable_data_events = false

default_tags = {
  Project    = "multicloud-security-baseline"
  Owner      = "Naveen Kumar"
  CostCenter = "IT"
}

# ---------------- GCP ----------------
gcp_project_id         = "your-gcp-project-id"  # required if deploy_gcp=true
gcp_region             = "asia-south1"
gcp_security_email     = "you@company.com"      # optional
gcp_log_bucket_location = "ASIA"
