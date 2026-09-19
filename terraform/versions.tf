terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.3"
    }
  }

  # The bucket is passed at init time (-backend-config=bucket=...) so that the
  # state location follows the target project.
  backend "gcs" {
    prefix = "semgate-example"
  }
}
