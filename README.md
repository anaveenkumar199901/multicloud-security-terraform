# Multicloud Security Baseline (Terraform) — Production-grade (AWS + GCP)

This repo is a **working, production-style** baseline that a Security/Platform Engineer can deploy to:
- **AWS (single account)**
- **GCP (single project)**
…from the **same Terraform repo**, with simple toggles.

> ✅ Designed to be human-readable, modular, and safe-by-default.
> ✅ Works with Terraform `>= 1.5`, AWS provider `>= 5`, Google provider `>= 5`.

---

## What it deploys

### AWS baseline (module `aws-baseline`)
**Logging & audit**
- KMS key with service permissions (CloudTrail + Config)
- Central S3 log bucket (SSE-KMS, versioning, public access blocked, lifecycle)
- CloudTrail (multi-region, global events, KMS encrypted)

**Configuration & compliance**
- AWS Config recorder + delivery channel
- Baseline managed rules: S3 public read/write prohibited, Root MFA, IAM password policy

**Threat detection & alerting**
- GuardDuty enabled
- Security Hub enabled
- EventBridge routes GuardDuty + SecurityHub findings to SNS
- Optional SNS email subscription

### GCP baseline (module `gcp-baseline`)
**Logging & audit**
- Enables required APIs
- KMS key ring + CMEK crypto key
- Central GCS log bucket (CMEK, uniform access, versioning)
- Cloud Logging sink exports Cloud Audit Logs to bucket

**Detection signal & alerting**
- Log-based metric for `SetIamPolicy` calls (IAM policy changes)
- Monitoring email notification channel + alert policy (optional)

---

## Prerequisites

### Terraform
- Terraform >= 1.5

### AWS auth
- Use a profile/SSO/env vars with permissions to create KMS/S3/CloudTrail/Config/GuardDuty/SecurityHub/SNS/EventBridge.

### GCP auth
- Recommended: Application Default Credentials
  ```bash
  gcloud auth application-default login
  ```
- Or set `GOOGLE_APPLICATION_CREDENTIALS` to a service account JSON with appropriate permissions.

---

## Quick Start

1) Copy tfvars:
```bash
cp terraform.tfvars.example terraform.tfvars
```

2) Edit `terraform.tfvars`:
- AWS: `aws_security_email` (optional)
- GCP: `gcp_project_id` (required to deploy GCP), `gcp_security_email` (optional)

3) Deploy:
```bash
terraform init
terraform plan  -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

4) Confirm emails:
- AWS SNS subscription confirmation (if you set `aws_security_email`)
- GCP Monitoring notification channel verification may be required (org dependent)

---

## Deploy only one cloud

In `terraform.tfvars`:
- `deploy_aws = false` → skip AWS
- `deploy_gcp = false` → skip GCP

---

## Production notes (recommended next steps)

- Use a **remote backend** for state (S3+DynamoDB or GCS). Example templates in `backends/`.
- Put each environment into separate state:
  - Workspaces OR separate backend key/prefix
- Consider org-level setups:
  - AWS Organizations + delegated admin for GuardDuty/SecurityHub org
  - GCP org/folder policies + Security Command Center

---

## Repo layout

- `modules/aws-baseline` — AWS security baseline
- `modules/gcp-baseline` — GCP security baseline
- `backends/` — sample remote backend configs (optional)
