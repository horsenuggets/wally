terraform {
  required_version = ">= 1.0"

  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 6.0"
    }
  }
}

provider "github" {
  owner = "horsenuggets"
}

module "repo" {
  source     = "../submodules/luau-cicd/Terraform/Modules/LuauRepo"
  repository = "wally"

  main_checks = [
    "Build",
    "Clippy",
    "Format",
    "Test",
  ]

  release_checks = [
    "Build test - Linux",
    "Build test - macOS",
    "Build test - Windows",
    "Validate PR title",
    "Validate version",
    "Verify diff matches main",
  ]
}
