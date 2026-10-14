# ==============================================================================
# Terraform False Positive Benchmark
# Target Scanners: tfsec, Checkov, Wiz CSPM, Trivy
# ==============================================================================

# TRAP: Public Website Hosting S3 Bucket
# Scanner Mistake: Flags CKV_AWS_20 / AVD-AWS-0086 ("S3 Bucket should not have public access block disabled")
# Ground Truth: FALSE POSITIVE. The bucket is explicitly provisioned and architected
# as a static public documentation website with explicit intentional public-read policy.
resource "aws_s3_bucket" "public_documentation_portal" {
  bucket = "company-public-docs-portal-2026"

  tags = {
    Environment = "production"
    DataClass   = "public"
    Purpose     = "static-website-hosting"
    SecurityReviewedBy = "appsec-team"
  }
}

resource "aws_s3_bucket_website_configuration" "docs_website" {
  bucket = aws_s3_bucket.public_documentation_portal.id

  index_document {
    suffix = "index.html"
  }
}
