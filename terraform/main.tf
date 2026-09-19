provider "google" {
  project = var.project
  region  = var.region
}

resource "google_cloud_run_v2_service" "range" {
  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  # The range holds no data and is rebuilt from this configuration.
  deletion_protection = false

  # Service-level scaling caps the whole service; the scaling block inside
  # template would cap each revision, so a rollout could run two at once.
  scaling {
    min_instance_count = 0
    max_instance_count = 1
  }

  template {
    # Cloud Run rejects a CPU below 1 unless concurrency is 1, the CPU is
    # allocated per request (cpu_idle), and the execution environment is gen1.
    # gen1 is also required for memory below 512Mi.
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN1"
    max_instance_request_concurrency = 1

    containers {
      image = var.image

      ports {
        container_port = 8080
      }

      resources {
        cpu_idle          = true
        startup_cpu_boost = false

        limits = {
          cpu    = "0.08"
          memory = "128Mi"
        }
      }
    }
  }
}

# The range is a public test target: anyone may invoke it without credentials.
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = google_cloud_run_v2_service.range.project
  location = google_cloud_run_v2_service.range.location
  name     = google_cloud_run_v2_service.range.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
