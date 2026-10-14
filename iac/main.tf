resource "aws_s3_bucket" "public_documentation_portal" {
  bucket = "company-public-docs-portal-2026"

  tags = {
    Environment = "production"
    DataClass   = "public"
    Purpose     = "static-website-hosting"
  }
}

resource "aws_s3_bucket_website_configuration" "docs_website" {
  bucket = aws_s3_bucket.public_documentation_portal.id

  index_document {
    suffix = "index.html"
  }
}
