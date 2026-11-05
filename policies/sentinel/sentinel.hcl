# HashiCorp Sentinel Policy Set Configuration (AWS & Azure)
import "module" "tfplan-functions" {
  source = "https://raw.githubusercontent.com/hashicorp/terraform-guides/master/governance/third-generation/common-functions/tfplan-functions/tfplan-functions.sentinel"
}

policy "enforce-aws-s3-block-public-access" {
  source            = "./aws/enforce-aws-s3-block-public-access.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "enforce-azurerm-storage-https-only" {
  source            = "./azure/enforce-azurerm-storage-https-only.sentinel"
  enforcement_level = "hard-mandatory"
}
