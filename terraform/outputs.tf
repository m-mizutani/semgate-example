output "service_url" {
  description = "Public URL of the deployed range (guarded when the API key is wired in)"
  value       = google_cloud_run_v2_service.range.uri
}

output "noguard_service_url" {
  description = "Public URL of the same range with no guard"
  value       = google_cloud_run_v2_service.range_noguard.uri
}

output "image" {
  description = "Container image the service currently runs"
  value       = google_cloud_run_v2_service.range.template[0].containers[0].image
}

output "typesafe_api_key_secret" {
  description = "Secret Manager secret that holds the TypeSafe (Jev) API key"
  value       = google_secret_manager_secret.typesafe_api_key.secret_id
}

output "guard_enabled" {
  description = "Whether the deployed range reads the API key, and therefore runs the guard"
  value       = var.typesafe_api_key_version != null
}
