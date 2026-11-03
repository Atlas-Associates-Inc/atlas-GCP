# Static security fixture; intentionally unsafe, never deploy.
resource "google_cloud_run_v2_service" "api" {
  name     = "api"
  project  = "atlas-fixture"
  location = "us-central1"
  ingress  = "INGRESS_TRAFFIC_ALL"
  template {
    service_account = "123456789-compute@developer.gserviceaccount.com"
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello"
    }
  }
}

resource "google_cloud_run_service_iam_member" "public" {
  project  = "atlas-fixture"
  location = "us-central1"
  service  = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloudfunctions2_function" "worker" {
  name     = "worker"
  project  = "atlas-fixture"
  location = "us-central1"
  build_config {
    runtime     = "nodejs22"
    entry_point = "handler"
    source {
      storage_source {
        bucket = "atlas-fixture-source"
        object = "worker.zip"
      }
    }
  }
  service_config {
    service_account_email = "123456789-compute@developer.gserviceaccount.com"
    ingress_settings      = "ALLOW_ALL"
  }
}

resource "google_project_iam_member" "default_editor" {
  project = "atlas-fixture"
  role    = "roles/editor"
  member  = "serviceAccount:123456789-compute@developer.gserviceaccount.com"
}

resource "google_project_iam_member" "default_secrets" {
  project = "atlas-fixture"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:123456789-compute@developer.gserviceaccount.com"
}

resource "google_service_account_iam_member" "impersonate_vault" {
  service_account_id = "projects/atlas-fixture/serviceAccounts/vault-reader@atlas-fixture.iam.gserviceaccount.com"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:123456789-compute@developer.gserviceaccount.com"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = "atlas-fixture"
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "unrestricted"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
