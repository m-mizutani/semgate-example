output "service_url" {
  description = "Public URL of the deployed range"
  value       = google_cloud_run_v2_service.range.uri
}

output "image" {
  description = "Container image the service currently runs"
  value       = google_cloud_run_v2_service.range.template[0].containers[0].image
}
