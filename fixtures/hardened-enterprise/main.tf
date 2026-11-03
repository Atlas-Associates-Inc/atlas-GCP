# Static comparison fixture; no deployment or live-policy verification implied.
resource "google_service_account" "runtime" {
  project    = "atlas-fixture"
  account_id = "api-runtime"
}

resource "google_cloud_run_v2_service" "api" {
  name     = "api"
  project  = "atlas-fixture"
  location = "us-central1"
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  template {
    service_account = google_service_account.runtime.email
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello"
    }
  }
}

resource "google_project_iam_custom_role" "runtime_logs" {
  project     = "atlas-fixture"
  role_id     = "runtimeLogWriter"
  title       = "Runtime log writer"
  permissions = ["logging.logEntries.create"]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = "atlas-fixture"
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "acme-api"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }
  attribute_condition = "attribute.repository == \"acme/api\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
