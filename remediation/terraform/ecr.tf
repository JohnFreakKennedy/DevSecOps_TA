# Images are referenced by digest, and tags cannot be overwritten. What was scanned is what runs.
resource "aws_ecr_repository" "service" {
  for_each = var.services

  name                 = each.key
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
  }
}

# cosign signatures, kept apart from the images (COSIGN_REPOSITORY in the deploy job). Of the CI
# roles, only deploy and the admin apply role can write here; the build role cannot plant or
# block a signature. Forging one needs the signing key, which only deploy can use. Tags stay
# mutable because cosign adds a new signature to the same tag when a digest is redeployed.
resource "aws_ecr_repository" "signatures" {
  name                 = "image-signatures"
  image_tag_mutability = "MUTABLE"

  encryption_configuration {
    encryption_type = "KMS"
  }
}
