provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.default_tags
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}
