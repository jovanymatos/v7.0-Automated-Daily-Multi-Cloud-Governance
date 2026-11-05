package wiz

# Auto-generated Wiz Custom CCR (OPA Rego) for Bank Mandatory Tag Governance [CCM GRC-01, FFIEC]
# Detects out-of-band console drift where resources bypass Terraform Checkov/Sentinel gates

default result = "PASS"

result = "FAIL" {
    not input.tags.CostCenter
}

result = "FAIL" {
    not input.tags.DataClassification
}

currentConfiguration := sprintf("Resource %v is missing mandatory bank governance tags (CostCenter / DataClassification)", [input.id])
expectedConfiguration := "All production AWS and Azure resources must carry valid CostCenter and DataClassification tags"
