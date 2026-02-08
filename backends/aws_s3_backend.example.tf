# Example remote state for AWS (S3 + DynamoDB)
# Copy to `backend.tf` and fill values, then run `terraform init -reconfigure`

terraform {
  backend "s3" {
    bucket         = "YOUR-TFSTATE-BUCKET"
    key            = "multicloud-security/prod/terraform.tfstate"
    region         = "ap-south-1"
    dynamodb_table = "YOUR-TFSTATE-LOCK-TABLE"
    encrypt        = true
  }
}
