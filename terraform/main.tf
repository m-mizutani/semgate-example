provider "google" {
  project = var.project
  region  = var.region
}

# Every setting the guarded and unguarded services must share lives here, so a
# change to one of them cannot be applied to only one service. The services
# differ only in name, identity, and whether TYPESAFE_API_KEY is present.
locals {
  ingress        = "INGRESS_TRAFFIC_ALL"
  min_instances  = 0
  max_instances  = 1
  container_port = 8080

  # Cloud Run rejects a CPU below 1 unless concurrency is 1, the CPU is
  # allocated per request (cpu_idle), and the execution environment is gen1.
  # gen1 is also required for memory below 512Mi.
  execution_environment = "EXECUTION_ENVIRONMENT_GEN1"
  request_concurrency   = 1
  cpu_limit             = "0.08"
  memory_limit          = "128Mi"
}

# Holds the TypeSafe (Jev) API key the guarded service reads at startup.
# Terraform creates the secret but never a version: the key is added with
# `gcloud secrets versions add`, so it stays out of the Terraform state, which
# is kept in a GCS bucket.
resource "google_secret_manager_secret" "typesafe_api_key" {
  secret_id = "${var.service_name}-typesafe-api-key"

  replication {
    auto {}
  }
}

# Each service runs as its own identity so that the no-guard service is not
# merely configured without the API key — it cannot read it.
resource "google_service_account" "range" {
  account_id   = var.service_name
  display_name = "Injection range with the semgate guard"
}

resource "google_service_account" "range_noguard" {
  account_id   = "${var.service_name}-noguard"
  display_name = "Injection range without a guard"
}

resource "google_secret_manager_secret_iam_member" "range_api_key_accessor" {
  secret_id = google_secret_manager_secret.typesafe_api_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.range.email}"
}

resource "google_cloud_run_v2_service" "range" {
  name     = var.service_name
  location = var.region
  ingress  = local.ingress

  # The range holds no data and is rebuilt from this configuration.
  deletion_protection = false

  # Service-level scaling caps the whole service; the scaling block inside
  # template would cap each revision, so a rollout could run two at once.
  scaling {
    min_instance_count = local.min_instances
    max_instance_count = local.max_instances
  }

  template {
    service_account = google_service_account.range.email

    execution_environment            = local.execution_environment
    max_instance_request_concurrency = local.request_concurrency

    containers {
      image = var.image

      ports {
        container_port = local.container_port
      }

      # The server enables the guard only when TYPESAFE_API_KEY is set. Leaving
      # typesafe_api_key_version unset deploys the service without the variable,
      # so the first apply succeeds before any key has been stored instead of
      # failing on a secret version that does not exist yet.
      dynamic "env" {
        for_each = var.typesafe_api_key_version == null ? [] : [var.typesafe_api_key_version]

        content {
          name = "TYPESAFE_API_KEY"

          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.typesafe_api_key.secret_id
              version = env.value
            }
          }
        }
      }

      resources {
        cpu_idle          = true
        startup_cpu_boost = false

        limits = {
          cpu    = local.cpu_limit
          memory = local.memory_limit
        }
      }
    }
  }

  # The revision fails to start if its identity cannot read the secret.
  depends_on = [google_secret_manager_secret_iam_member.range_api_key_accessor]
}

# The same range with no API key, and therefore no guard: the before/after pair
# the guard is measured against. It differs from
# google_cloud_run_v2_service.range only in its name, its identity, and the
# absence of the TYPESAFE_API_KEY variable; everything else comes from the same
# locals.
resource "google_cloud_run_v2_service" "range_noguard" {
  name     = "${var.service_name}-noguard"
  location = var.region
  ingress  = local.ingress

  deletion_protection = false

  scaling {
    min_instance_count = local.min_instances
    max_instance_count = local.max_instances
  }

  template {
    service_account = google_service_account.range_noguard.email

    execution_environment            = local.execution_environment
    max_instance_request_concurrency = local.request_concurrency

    containers {
      image = var.image

      ports {
        container_port = local.container_port
      }

      resources {
        cpu_idle          = true
        startup_cpu_boost = false

        limits = {
          cpu    = local.cpu_limit
          memory = local.memory_limit
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

resource "google_cloud_run_v2_service_iam_member" "public_invoker_noguard" {
  project  = google_cloud_run_v2_service.range_noguard.project
  location = google_cloud_run_v2_service.range_noguard.location
  name     = google_cloud_run_v2_service.range_noguard.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
