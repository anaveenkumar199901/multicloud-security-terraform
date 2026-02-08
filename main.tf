locals {
  name_prefix = "sec-${var.environment}"
}

# AWS baseline (single account)
module "aws_baseline" {
  count  = var.deploy_aws ? 1 : 0
  source = "./modules/aws-baseline"

  name_prefix                   = local.name_prefix
  cloudtrail_enable_data_events = var.cloudtrail_enable_data_events
  sns_email_target              = var.aws_security_email
}

# GCP baseline (single project)
module "gcp_baseline" {
  count  = var.deploy_gcp ? 1 : 0
  source = "./modules/gcp-baseline"

  name_prefix         = local.name_prefix
  project_id          = var.gcp_project_id
  region              = var.gcp_region
  log_bucket_location = var.gcp_log_bucket_location
  alert_email         = var.gcp_security_email
}
