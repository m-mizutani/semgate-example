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
