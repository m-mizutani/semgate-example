variable "project" {
  description = "Google Cloud project ID to deploy into"
  type        = string
}

variable "region" {
  description = "Cloud Run region"
  type        = string
  default     = "asia-northeast1"
}

variable "service_name" {
  description = "Cloud Run service name"
  type        = string
  default     = "semgate-example"
}

variable "image" {
  description = "Container image to run, including the tag"
  type        = string
}

variable "typesafe_api_key_version" {
  description = <<-EOT
    Secret Manager version of the TypeSafe (Jev) API key the guarded service
    reads as TYPESAFE_API_KEY: "latest" or a version number. Leave it unset
    until the key has been stored with `gcloud secrets versions add`; the
    guarded service then deploys without the variable and runs unguarded.
  EOT
  type        = string
  default     = null
}
