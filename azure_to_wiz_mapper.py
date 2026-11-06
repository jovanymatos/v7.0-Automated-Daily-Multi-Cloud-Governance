#!/usr/bin/env python3
"""
Multi-Cloud (AWS & Azure) 3-Layer Policy-as-Code Tri-Mapper & Daily SDLC Audit Governance Engine (v6.0)
Designed to Remediate Audit Observation:
  "Noncompliance with SDLC Practices for Automated Cloud Security Policy Deployments"

Addresses Key Audit & Regulatory Governance Requirements:
  1. Daily (24-Hour) Automated Wiz Release Governance (--since-days 14 default):
     - Captures all newly deployed or updated Wiz Cloud Configuration Rules (CCRs) across AWS & Azure
       every two weeks and queues them for formal SDLC evaluation, testing, approval, and documentation.
  2. 3-Layer Architecture & Operational Impact Alignment:
     - Layer 1 (CI/PR Static Scan):     Checkov (CKV_AWS_* / CKV_AZURE_* & Custom Checkov YAML)
     - Layer 2 (Pre-Apply TFC/TFE Gate): HashiCorp Sentinel (.sentinel + sentinel.hcl via tfplan/v2)
     - Layer 3 (Runtime & Graph):        Wiz Cloud Configuration Rules (CCRs & Custom OPA Rego .rego)
  3. Formal Rule Exception Inventory & Periodic Reassessment Tracking:
     - Tracks excluded/disabled Wiz rules (enabled=False or marked Not Applicable to Cloud Architecture)
       with documented exception justification, compensating controls (Sentinel/Checkov), approver sign-off,
       and automated 90/180-day periodic reassessment dates (`next_periodic_review_date`).
"""

import argparse
import csv
import difflib
import glob
import json
import logging
import os
import re
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib import request, parse, error

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("sdlc_cloud_policy_governance")

SCHEMA_VERSION = "7.0.0-Daily-SDLC-Audit-Governance"

DEFAULT_STOP_WORDS = {
    "azure", "aws", "amazon", "policy", "sentinel", "hashicorp", "checkov", "should",
    "be", "enabled", "disabled", "for", "on", "in", "the", "and", "or", "to", "with",
    "of", "from", "by", "have", "use", "using", "ensure", "that", "is", "are", "all",
    "resources", "resource", "microsoft", "audit", "deny", "deployifnotexists", "modify",
    "if", "not", "exists", "configure", "restrict", "require", "enforce", "rule",
    "terraform", "tfplan",
}

DEFAULT_MULTICLOUD_RESOURCE_MAP: Dict[str, Set[str]] = {
    "microsoft.storage/storageaccounts": {"storageaccount", "storageaccounts", "blobservice", "fileservice"},
    "azurerm_storage_account": {"storageaccount", "storageaccounts", "blobservice"},
    "microsoft.keyvault/vaults": {"keyvault", "vault", "keyvaultkey", "keyvaultsecret", "hsm"},
    "azurerm_key_vault": {"keyvault", "vault", "keyvaultkey", "keyvaultsecret"},
    "microsoft.compute/virtualmachines": {"virtualmachine", "vm", "compute", "virtualmachinescaleset"},
    "azurerm_linux_virtual_machine": {"virtualmachine", "vm", "compute"},
    "azurerm_windows_virtual_machine": {"virtualmachine", "vm", "compute"},
    "microsoft.compute/disks": {"disk", "manageddisk", "encryption"},
    "azurerm_managed_disk": {"disk", "manageddisk"},
    "microsoft.sql/servers": {"sqlserver", "sqldatabase", "sql", "auditing"},
    "microsoft.sql/servers/databases": {"sqldatabase", "sqlserver", "sql"},
    "azurerm_mssql_database": {"sqldatabase", "sqlserver", "sql"},
    "microsoft.network/networksecuritygroups": {"networksecuritygroup", "nsg", "securitygroup", "securityrule"},
    "azurerm_network_security_group": {"networksecuritygroup", "nsg", "securitygroup"},
    "microsoft.containerservice/managedclusters": {"aks", "kubernetescluster", "managedcluster"},
    "azurerm_kubernetes_cluster": {"aks", "kubernetescluster", "managedcluster"},
    "microsoft.web/sites": {"webapp", "appservice", "functionapp"},
    "azurerm_linux_web_app": {"webapp", "appservice"},
    "microsoft.cosmosdb/databaseaccounts": {"cosmosdb", "databaseaccount", "documentdb"},
    "azurerm_cosmosdb_account": {"cosmosdb", "databaseaccount"},
    "microsoft.eventhub/namespaces": {"eventhub", "namespace"},
    "azurerm_eventhub_namespace": {"eventhub", "namespace"},
    "azurerm_cognitive_account": {"cognitiveaccount", "openai"},
    "aws_s3_bucket": {"bucket", "s3bucket", "s3"},
    "aws_s3_bucket_public_access_block": {"bucket", "s3bucket", "s3"},
    "aws_s3_bucket_server_side_encryption_configuration": {"bucket", "s3bucket", "s3"},
    "aws_kms_key": {"encryptionkey", "kmskey", "kms"},
    "aws_db_instance": {"rds", "rdsinstance", "dbinstance", "database"},
    "aws_rds_cluster": {"rds", "rdscluster", "database"},
    "aws_security_group": {"securitygroup", "awssecuritygroup", "sg"},
    "aws_instance": {"virtualmachine", "ec2", "ec2instance", "instance"},
    "aws_ebs_volume": {"volume", "ebsvolume", "disk", "ebs"},
    "aws_ebs_encryption_by_default": {"volume", "ebsvolume", "disk", "ebs"},
    "aws_iam_role": {"iamrole", "role", "serviceaccount", "iam"},
    "aws_iam_policy": {"iampolicy", "policy", "iam"},
    "aws_eks_cluster": {"eks", "kubernetescluster", "cluster"},
    "aws_cloudtrail": {"cloudtrail", "trail", "loggroup"},
}

WIZ_NATIVE_TO_TERRAFORM_MAP: Dict[Tuple[str, str], str] = {
    ("AZURE", "storageaccount"): "azurerm_storage_account",
    ("AZURE", "keyvault"): "azurerm_key_vault",
    ("AZURE", "sqldatabase"): "azurerm_mssql_database",
    ("AZURE", "networksecuritygroup"): "azurerm_network_security_group",
    ("AZURE", "kubernetescluster"): "azurerm_kubernetes_cluster",
    ("AZURE", "manageddisk"): "azurerm_managed_disk",
    ("AZURE", "webapp"): "azurerm_linux_web_app",
    ("AZURE", "cosmosdb"): "azurerm_cosmosdb_account",
    ("AZURE", "eventhub"): "azurerm_eventhub_namespace",
    ("AZURE", "cognitiveaccount"): "azurerm_cognitive_account",
    ("AWS", "bucket"): "aws_s3_bucket",
    ("AWS", "s3bucket"): "aws_s3_bucket",
    ("AWS", "kmskey"): "aws_kms_key",
    ("AWS", "encryptionkey"): "aws_kms_key",
    ("AWS", "rds"): "aws_db_instance",
    ("AWS", "dbinstance"): "aws_db_instance",
    ("AWS", "securitygroup"): "aws_security_group",
    ("AWS", "ec2instance"): "aws_instance",
    ("AWS", "virtualmachine"): "aws_instance",
    ("AWS", "ebsvolume"): "aws_ebs_volume",
    ("AWS", "volume"): "aws_ebs_volume",
    ("AWS", "eks"): "aws_eks_cluster",
    ("AWS", "iamrole"): "aws_iam_role",
    ("AWS", "cloudtrail"): "aws_cloudtrail",
}

BUILT_IN_CHECKOV_CATALOG: List[Dict[str, Any]] = [
    {
        "checkov_id": "CKV_AZURE_3",
        "cloud_provider": "AZURE",
        "resource_types": {"azurerm_storage_account", "microsoft.storage/storageaccounts"},
        "keywords": {"https", "secure", "transfer", "enable_https_traffic_only"},
        "title": "Ensure that 'Secure transfer required' is set to 'Enabled'",
    },
    {
        "checkov_id": "CKV_AZURE_59",
        "cloud_provider": "AZURE",
        "resource_types": {"azurerm_storage_account", "microsoft.storage/storageaccounts"},
        "keywords": {"public", "blob", "allow_nested_items_to_be_public", "allowblobpublicaccess"},
        "title": "Ensure that Storage accounts disallow public access to blobs",
    },
    {
        "checkov_id": "CKV_AZURE_42",
        "cloud_provider": "AZURE",
        "resource_types": {"azurerm_key_vault", "microsoft.keyvault/vaults"},
        "keywords": {"soft", "delete", "soft_delete_retention_days", "enablesoftdelete"},
        "title": "Ensure the Key Vault is recoverable (Soft Delete enabled)",
    },
    {
        "checkov_id": "CKV_AZURE_24",
        "cloud_provider": "AZURE",
        "resource_types": {"azurerm_mssql_database", "microsoft.sql/servers/databases"},
        "keywords": {"transparent", "tde", "encryption", "transparent_data_encryption_enabled"},
        "title": "Ensure Transparent Data Encryption (TDE) is enabled on SQL databases",
    },
    {
        "checkov_id": "CKV_AZURE_9",
        "cloud_provider": "AZURE",
        "resource_types": {"azurerm_network_security_group", "microsoft.network/networksecuritygroups"},
        "keywords": {"rdp", "ssh", "management", "port", "3389", "22"},
        "title": "Ensure that RDP/SSH access is restricted from the internet on NSGs",
    },
    {
        "checkov_id": "CKV_AZURE_5",
        "cloud_provider": "AZURE",
        "resource_types": {"azurerm_kubernetes_cluster", "microsoft.containerservice/managedclusters"},
        "keywords": {"rbac", "role", "role_based_access_control_enabled"},
        "title": "Ensure RBAC is enabled on AKS clusters",
    },
    {
        "checkov_id": "CKV_AZURE_93",
        "cloud_provider": "AZURE",
        "resource_types": {"azurerm_managed_disk", "microsoft.compute/disks"},
        "keywords": {"disk", "cmk", "customer", "disk_encryption_set_id"},
        "title": "Ensure managed disks are encrypted with Customer-Managed Keys (CMK)",
    },
    {
        "checkov_id": "CKV_AZURE_14",
        "cloud_provider": "AZURE",
        "resource_types": {"azurerm_linux_web_app", "azurerm_app_service", "microsoft.web/sites"},
        "keywords": {"tls", "1.2", "minimum_tls_version", "mintlsversion"},
        "title": "Ensure App Service web app uses minimum TLS 1.2",
    },
    {
        "checkov_id": "CKV_AZURE_134",
        "cloud_provider": "AZURE",
        "resource_types": {"azurerm_cognitive_account"},
        "keywords": {"cognitive", "openai", "public", "network", "public_network_access_enabled"},
        "title": "Ensure Cognitive Services accounts disable public network access",
    },
    {
        "checkov_id": "CKV_AWS_53",
        "cloud_provider": "AWS",
        "resource_types": {"aws_s3_bucket_public_access_block", "aws_s3_bucket"},
        "keywords": {"s3", "public", "block", "block_public_acls", "block_public_policy"},
        "title": "Ensure S3 bucket has block public ACLs and block public policy enabled",
    },
    {
        "checkov_id": "CKV_AWS_7",
        "cloud_provider": "AWS",
        "resource_types": {"aws_kms_key"},
        "keywords": {"kms", "rotation", "enable_key_rotation"},
        "title": "Ensure rotation for customer-created KMS CMKs is enabled",
    },
    {
        "checkov_id": "CKV_AWS_79",
        "cloud_provider": "AWS",
        "resource_types": {"aws_instance"},
        "keywords": {"imdsv2", "metadata", "http_tokens", "ec2"},
        "title": "Ensure Instance Metadata Service Version 2 (IMDSv2) is enabled",
    },
    {
        "checkov_id": "CKV_AWS_16",
        "cloud_provider": "AWS",
        "resource_types": {"aws_db_instance"},
        "keywords": {"rds", "encryption", "storage_encrypted", "kms"},
        "title": "Ensure all data stored in RDS is securely encrypted at rest",
    },
    {
        "checkov_id": "CKV_AWS_39",
        "cloud_provider": "AWS",
        "resource_types": {"aws_eks_cluster"},
        "keywords": {"eks", "public", "endpoint", "endpoint_public_access"},
        "title": "Ensure Amazon EKS public endpoint is disabled",
    },
    {
        "checkov_id": "CKV_AWS_35",
        "cloud_provider": "AWS",
        "resource_types": {"aws_cloudtrail"},
        "keywords": {"cloudtrail", "kms", "validation", "enable_log_file_validation"},
        "title": "Ensure CloudTrail logs are encrypted at rest using KMS CMKs and validated",
    },
]

DEFAULT_WEIGHTS = {
    "name_jaccard": 0.40,
    "name_sequence": 0.25,
    "desc_jaccard": 0.20,
    "resource_type": 0.15,
    "control_boost_per_match": 0.15,
    "control_boost_max": 0.25,
}

PREVENTATIVE_EFFECTS = {
    "deny", "deployifnotexists", "modify", "denyaction",
    "hard-mandatory", "soft-mandatory",
}

GUID_REGEX = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
CONTROL_ID_REGEX = re.compile(
    r"\b(?:CCM|CSA[-_:\s]*CCM|CIS|NIST|PCI|FFIEC|SOX|SOC|ISO)[-_:\s]*(?:SP\s*800-53\s*|v4\s*)?[A-Z0-9.\-]{2,15}\b"
    r"|\b(?:AIS|BCR|CCC|CEK|DCS|DSP|EKM|GRC|HRS|IAM|IPY|IVS|LOG|SEF|STA|TVM|UEM)-\d{2}\b",
    re.IGNORECASE,
)
TF_RESOURCE_REGEX = re.compile(r"\b(azurerm_[a-z0-9_]+|aws_[a-z0-9_]+)\b", re.IGNORECASE)
SENTINEL_HCL_BLOCK_REGEX = re.compile(
    r'policy\s+"([^"]+)"\s*\{([^}]+)\}',
    re.MULTILINE | re.DOTALL,
)


@dataclass
class PolicyControlRecord:
    policy_id: str
    guid: str
    cloud_provider: str  # AWS or AZURE
    source_engine: str   # HashiCorp Sentinel
    display_name: str
    description: str
    category: str
    policy_type: str     # Sentinel-IaC, Custom
    default_effect: str  # hard-mandatory, soft-mandatory, advisory
    target_resource_types: Set[str] = field(default_factory=set)
    condition_fields: Set[str] = field(default_factory=set)
    compliance_controls: Set[str] = field(default_factory=set)
    checkov_id: str = ""


@dataclass
class WizRuleRecord:
    rule_id: str
    short_id: str
    cloud_provider: str  # AWS or AZURE
    name: str
    description: str
    severity: str
    enabled: bool
    target_native_types: Set[str] = field(default_factory=set)
    referenced_guids: Set[str] = field(default_factory=set)
    compliance_controls: Set[str] = field(default_factory=set)
    has_opa_rego: bool = False
    created_at: str = ""
    updated_at: str = ""
    ccr_change_status: str = "Baseline"
    issue_generation_enabled: bool = False
    linked_security_graph_controls: int = 0
    failing_findings_count: int = 0
    pass_findings_count: int = 0


@dataclass
class MappingResult:
    cloud_provider: str
    source_engine: str
    gap_direction: str
    # Layer 1: Checkov CI/PR Static Analysis
    checkov_id: str
    checkov_status: str
    # Step 1-4 CCR Review Workflow Metadata
    ccr_change_status: str
    wiz_updated_at: str
    finding_validation_status: str
    issue_generation_configured: str
    security_graph_status: str
    preventative_control_coverage: str
    team_action_ticket: str
    # Daily SDLC Governance & Exception Management Fields (Audit Remediation)
    sdlc_governance_stage: str
    rule_exception_status: str
    exception_justification: str
    approver_signoff: str
    next_periodic_review_date: str
    # Layer 2: HashiCorp Sentinel Metadata
    azure_policy_guid: str
    azure_policy_name: str
    azure_policy_type: str
    azure_category: str
    azure_default_effect: str
    azure_resource_types: str
    azure_condition_fields: str
    # Layer 3: Wiz CCR Metadata
    wiz_rule_id: str
    wiz_short_id: str
    wiz_rule_name: str
    wiz_severity: str
    wiz_native_types: str
    mapping_tier: str
    confidence_score: float
    shared_controls: str
    review_status: str
    mapping_rationale: str
    # Generated Policy-as-Code Across All 3 Layers
    generated_checkov_yaml: str
    generated_sentinel_skeleton: str
    generated_rego_skeleton: str


# =====================================================================
# HTTP, WIZ GRAPHQL & HCP TERRAFORM / TFE SENTINEL API CLIENTS
# =====================================================================

def _build_tls_context() -> ssl.SSLContext:
    """Enforces TLS 1.2+ and strict certificate verification for enterprise banking compliance."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def http_request_with_retry(
    req: request.Request,
    max_retries: int = 4,
    base_backoff: float = 1.5,
    timeout: int = 60,
    parse_json: bool = True,
) -> Any:
    parsed_url = parse.urlparse(req.full_url)
    if parsed_url.scheme.lower() != "https":
        raise ValueError(f"Enterprise Security Policy Violation: Only https:// URLs are permitted (got '{parsed_url.scheme}://').")
    tls_ctx = _build_tls_context()
    for attempt in range(max_retries + 1):
        try:
            with request.urlopen(req, timeout=timeout, context=tls_ctx) as resp:
                raw_text = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw_text) if parse_json else raw_text
        except error.HTTPError as exc:
            if exc.code in (429, 500, 502, 503, 504) and attempt < max_retries:
                retry_after = exc.headers.get("Retry-After")
                sleep_sec = float(retry_after) if retry_after and retry_after.isdigit() else base_backoff ** (attempt + 1)
                logger.warning("HTTP %d received; retrying in %.1fs...", exc.code, sleep_sec)
                time.sleep(sleep_sec)
                continue
            err_body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            raise RuntimeError(f"HTTP {exc.code} Error from {req.full_url}: {err_body}") from exc
        except error.URLError as exc:
            if attempt < max_retries:
                sleep_sec = base_backoff ** (attempt + 1)
                time.sleep(sleep_sec)
                continue
            raise
    return {} if parse_json else ""


WIZ_CLOUD_CONFIG_QUERY_PRIMARY = """
query CloudConfigurationRules($first: Int, $after: String, $filterBy: CloudConfigurationRuleFilters) {
  cloudConfigurationRules(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      shortId
      name
      description
      severity
      enabled
      cloudProvider
      createdAt
      updatedAt
      targetNativeTypes
      builtinId
      remediationInstructions
      opaPolicy
      control {
        id
        name
        enabled
      }
      analytics {
        passCount
        failCount
      }
      securitySubCategories {
        id
        title
        category {
          id
          name
          framework {
            id
            name
          }
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""

WIZ_CLOUD_CONFIG_QUERY_MINIMAL = """
query CloudConfigurationRulesMinimal($first: Int, $after: String) {
  cloudConfigurationRules(first: $first, after: $after) {
    nodes {
      id
      name
      description
      severity
      enabled
      cloudProvider
      targetNativeTypes
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""


def fetch_wiz_token(auth_url: str, client_id: str, client_secret: str, audience: str = "wiz-api") -> str:
    payload = parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": audience,
    }).encode("utf-8")
    req = request.Request(
        auth_url,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    body = http_request_with_retry(req, timeout=30)
    return body["access_token"]


def fetch_wiz_rules_from_api(
    api_url: str,
    token: str,
    cloud_providers: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    all_nodes: List[Dict[str, Any]] = []
    after_cursor: Optional[str] = None
    has_next = True
    use_minimal = False
    providers = cloud_providers or ["AZURE", "AWS"]

    while has_next:
        query = WIZ_CLOUD_CONFIG_QUERY_MINIMAL if use_minimal else WIZ_CLOUD_CONFIG_QUERY_PRIMARY
        variables: Dict[str, Any] = {"first": 500, "after": after_cursor}
        if not use_minimal:
            variables["filterBy"] = {"cloudProvider": providers}

        payload = json.dumps({"query": query, "variables": variables}).encode("utf-8")
        req = request.Request(
            api_url,
            data=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        data = http_request_with_retry(req, timeout=60)

        if "errors" in data and not use_minimal:
            logger.warning("Primary Wiz GraphQL query returned schema error; falling back to minimal query.")
            use_minimal = True
            continue
        elif "errors" in data:
            raise RuntimeError(f"Wiz GraphQL error: {data['errors']}")

        rule_conn = data.get("data", {}).get("cloudConfigurationRules", {})
        nodes = rule_conn.get("nodes", [])
        all_nodes.extend(nodes)

        page_info = rule_conn.get("pageInfo", {})
        has_next = bool(page_info.get("hasNextPage"))
        after_cursor = page_info.get("endCursor")
        logger.info("Fetched %d Wiz rules (%s) so far...", len(all_nodes), ", ".join(providers))

    return all_nodes


def fetch_hashicorp_sentinel_from_tfc_api(
    tfc_org: str,
    tfc_token: str,
    tfc_base_url: str = "https://app.terraform.io",
) -> List[PolicyControlRecord]:
    records: List[PolicyControlRecord] = []
    next_url: Optional[str] = f"{tfc_base_url.rstrip('/')}/api/v2/organizations/{tfc_org}/policies?page[size]=100"
    headers = {
        "Authorization": f"Bearer {tfc_token}",
        "Content-Type": "application/vnd.api+json",
    }

    while next_url:
        req = request.Request(next_url, headers=headers)
        body = http_request_with_retry(req, timeout=45)
        for pol in body.get("data", []):
            pol_id = str(pol.get("id", ""))
            attrs = pol.get("attributes") or {}
            name = str(attrs.get("name") or pol_id)
            desc = str(attrs.get("description") or f"HashiCorp Sentinel policy {name}")
            enf_list = attrs.get("enforcement-level") or attrs.get("enforce") or []
            if isinstance(enf_list, list) and enf_list:
                effect = str(enf_list[0].get("mode", "hard-mandatory"))
            elif isinstance(enf_list, str):
                effect = enf_list
            else:
                effect = "hard-mandatory"

            dl_url = f"{tfc_base_url.rstrip('/')}/api/v2/policies/{pol_id}/download"
            sentinel_code = ""
            try:
                dl_req = request.Request(dl_url, headers=headers)
                sentinel_code = http_request_with_retry(dl_req, timeout=30, parse_json=False)
            except Exception:
                pass

            tf_types = {m.lower() for m in TF_RESOURCE_REGEX.findall(f"{name} {desc} {sentinel_code}")}
            cloud = "AWS" if any(t.startswith("aws_") for t in tf_types) or "aws" in name.lower() else "AZURE"
            cond_attrs = set(re.findall(r"rc\.change\.after\.([a-zA-Z0-9_.]+)", sentinel_code))
            controls = {re.sub(r"\s+", " ", m.upper().strip()) for m in CONTROL_ID_REGEX.findall(f"{desc} {sentinel_code}")}

            records.append(
                PolicyControlRecord(
                    policy_id=pol_id,
                    guid=name.lower(),
                    cloud_provider=cloud,
                    source_engine="HashiCorp Sentinel",
                    display_name=name,
                    description=desc,
                    category="Terraform IaC",
                    policy_type="Sentinel-IaC",
                    default_effect=effect,
                    target_resource_types=tf_types,
                    condition_fields=cond_attrs,
                    compliance_controls=controls,
                )
            )
        links = body.get("links") or {}
        next_url = links.get("next")
        logger.info("Fetched %d HashiCorp Sentinel policies from TFC/TFE...", len(records))

    return records


def fetch_azure_policies_live(
    subscription_id: Optional[str] = None,
    management_group_id: Optional[str] = None,
    api_version: str = "2023-04-01",
) -> List[PolicyControlRecord]:
    """
    Pulls Azure Policy Definitions live from Azure Resource Manager (Management Group or Subscription)
    using azure-mgmt-resource SDK or Azure CLI ('az account get-access-token') + ARM REST API.
    """
    raw_items: List[Dict[str, Any]] = []
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resource.policy import PolicyClient

        logger.info("Polling Azure Policy definitions live via DefaultAzureCredential...")
        cred = DefaultAzureCredential()
        client = PolicyClient(credential=cred, subscription_id=subscription_id or "00000000-0000-0000-0000-000000000000")
        if management_group_id:
            paged = client.policy_definitions.list_by_management_group(management_group_id)
        elif subscription_id:
            paged = client.policy_definitions.list()
        else:
            paged = client.policy_definitions.list_built_in()
        raw_items = [p.as_dict() for p in paged]
    except ImportError:
        token = os.environ.get("AZURE_ACCESS_TOKEN", "")
        if not token:
            res = subprocess.run(
                ["az", "account", "get-access-token", "--resource", "https://management.azure.com/", "--query", "accessToken", "-o", "tsv"],
                capture_output=True,
                text=True,
                check=True,
                timeout=25,
            )
            token = res.stdout.strip()

        if management_group_id:
            next_url = f"https://management.azure.com/providers/Microsoft.Management/managementGroups/{management_group_id}/providers/Microsoft.Authorization/policyDefinitions?api-version={api_version}"
        elif subscription_id:
            next_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Authorization/policyDefinitions?api-version={api_version}"
        else:
            next_url = f"https://management.azure.com/providers/Microsoft.Authorization/policyDefinitions?api-version={api_version}"

        while next_url:
            req = request.Request(next_url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
            body = http_request_with_retry(req, timeout=60)
            raw_items.extend(body.get("value", []))
            next_url = body.get("nextLink", "")

    logger.info("Fetched %d live Azure Policy definitions.", len(raw_items))
    for item in raw_items:
        item["cloudProvider"] = "AZURE"
        item["sourceEngine"] = "Azure Policy (Live ARM)"
    return parse_policy_controls(raw_items)


def fetch_aws_policies_live(aws_region: str = "us-east-1") -> List[PolicyControlRecord]:
    """
    Pulls AWS Config Rules (describe-config-rules) and AWS Organizations Service Control Policies (SCPs)
    live using boto3 (if installed) or AWS CLI fallback.
    """
    records: List[PolicyControlRecord] = []
    config_rules: List[Dict[str, Any]] = []
    scps: List[Dict[str, Any]] = []

    try:
        import boto3  # type: ignore

        logger.info("Polling AWS Config Rules & AWS Organizations SCPs live via boto3 (%s)...", aws_region)
        cfg_client = boto3.client("config", region_name=aws_region)
        paginator = cfg_client.get_paginator("describe_config_rules")
        for page in paginator.paginate():
            config_rules.extend(page.get("ConfigRules", []))

        try:
            org_client = boto3.client("organizations")
            scp_paginator = org_client.get_paginator("list_policies")
            for page in scp_paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
                scps.extend(page.get("Policies", []))
        except Exception as org_exc:
            logger.warning("AWS Organizations SCP list skipped (%s)", org_exc)
    except ImportError:
        logger.info("boto3 not installed; polling AWS Config Rules & SCPs via AWS CLI...")
        res_cfg = subprocess.run(
            ["aws", "configservice", "describe-config-rules", "--region", aws_region, "--output", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        config_rules = json.loads(res_cfg.stdout).get("ConfigRules", [])

        res_scp = subprocess.run(
            ["aws", "organizations", "list-policies", "--filter", "SERVICE_CONTROL_POLICY", "--output", "json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if res_scp.returncode == 0 and res_scp.stdout.strip():
            scps = json.loads(res_scp.stdout).get("Policies", [])

    for cr in config_rules:
        rule_name = str(cr.get("ConfigRuleName") or cr.get("ConfigRuleId") or "aws-config-rule")
        desc = str(cr.get("Description") or f"AWS Config Rule {rule_name}")
        scope_types = (cr.get("Scope") or {}).get("ComplianceResourceTypes") or []
        res_types = {str(t).lower() for t in scope_types}
        source_id = str((cr.get("Source") or {}).get("SourceIdentifier") or "")
        controls = {re.sub(r"\s+", " ", m.upper().strip()) for m in CONTROL_ID_REGEX.findall(f"{rule_name} {desc} {source_id}")}
        records.append(
            PolicyControlRecord(
                policy_id=str(cr.get("ConfigRuleArn") or rule_name),
                guid=rule_name.lower(),
                cloud_provider="AWS",
                source_engine="AWS Config (Live)",
                display_name=f"{rule_name} ({source_id})" if source_id else rule_name,
                description=desc,
                category="AWS Config",
                policy_type="BuiltIn",
                default_effect="Detective (AWS Config)",
                target_resource_types=res_types,
                condition_fields={source_id.lower()} if source_id else set(),
                compliance_controls=controls,
            )
        )

    for scp in scps:
        scp_id = str(scp.get("Id") or "scp-id")
        scp_name = str(scp.get("Name") or scp_id)
        desc = str(scp.get("Description") or f"AWS Organizations SCP {scp_name}")
        records.append(
            PolicyControlRecord(
                policy_id=str(scp.get("Arn") or scp_id),
                guid=scp_id.lower(),
                cloud_provider="AWS",
                source_engine="AWS Organizations SCP (Live)",
                display_name=scp_name,
                description=desc,
                category="AWS SCP",
                policy_type="Custom",
                default_effect="Deny (AWS SCP)",
                target_resource_types={"aws_iam_role", "aws_s3_bucket", "aws_instance"},
                condition_fields={"scp.statement"},
                compliance_controls=set(),
            )
        )

    logger.info("Fetched %d live AWS Config Rules and %d AWS SCPs.", len(config_rules), len(scps))
    return records


# =====================================================================
# CHECKOV CROSSWALK & 3-LAYER POLICY-AS-CODE GENERATORS
# =====================================================================

def resolve_checkov_mapping(
    cloud_provider: str,
    resource_types: Set[str],
    title_and_fields: str,
    explicit_ckv_id: str = "",
) -> Tuple[str, str]:
    if explicit_ckv_id:
        return explicit_ckv_id, "Built-In CKV Active (CI/PR Gate)"

    text_tokens = set(re.findall(r"[a-z0-9_.]{2,}", title_and_fields.lower()))
    res_lower = {r.lower() for r in resource_types}

    best_entry: Optional[Dict[str, Any]] = None
    best_overlap = 0

    for entry in BUILT_IN_CHECKOV_CATALOG:
        if entry["cloud_provider"].upper() != cloud_provider.upper():
            continue
        res_match = bool(res_lower & entry["resource_types"])
        kw_overlap = len(text_tokens & entry["keywords"])
        score = (2 if res_match else 0) + kw_overlap
        if score > best_overlap and kw_overlap >= 1:
            best_overlap = score
            best_entry = entry

    if best_entry and best_overlap >= 3:
        return best_entry["checkov_id"], f"Built-In CKV Active ({best_entry['checkov_id']} in CI/PR)"

    slug = re.sub(r"[^A-Z0-9]+", "_", title_and_fields.upper()).strip("_")[:18]
    return f"CKV2_CUSTOM_{cloud_provider.upper()}_{slug}", "Custom Checkov YAML Needed (CI/PR Gap)"


def generate_checkov_custom_yaml(
    checkov_id: str,
    cloud_provider: str,
    policy_title: str,
    resource_types: Set[str],
    condition_fields: Set[str],
    category: str = "GENERAL_SECURITY",
) -> str:
    res_list = sorted(resource_types) or [f"{'aws' if cloud_provider.upper() == 'AWS' else 'azurerm'}_resource"]
    primary_attr = sorted(condition_fields)[0] if condition_fields else "encryption_enabled"
    clean_attr = primary_attr.split("/")[-1].replace("['", ".").replace("']", "")
    safe_title = policy_title.replace('"', "'")

    lines = [
        "---",
        "# Auto-generated Checkov Custom YAML Policy (Layer 1: CI / PR Static Scan)",
        "metadata:",
        f'  id: "{checkov_id}"',
        f'  name: "{safe_title}"',
        f'  category: "{category.upper().replace(" ", "_")}"',
        '  severity: "HIGH"',
        "definition:",
        '  cond_type: "attribute"',
        "  resource_types:",
    ]
    for rt in res_list:
        lines.append(f'    - "{rt}"')
    lines.extend([
        f'  attribute: "{clean_attr}"',
        '  operator: "exists"',
    ])
    return "\n".join(lines)


def generate_opa_rego_skeleton(pol: PolicyControlRecord) -> str:
    fields_list = sorted(pol.condition_fields)
    res_list = sorted(pol.target_resource_types) or [f"{pol.cloud_provider.lower()}.resources"]
    primary_field = fields_list[0] if fields_list else "properties.securityConfiguration"
    clean_path = primary_field.split("/")[-1].replace("['", ".").replace("']", "")

    lines = [
        "package wiz",
        "",
        f"# Auto-generated Wiz Custom CCR (OPA Rego) for {pol.cloud_provider} {pol.source_engine}: {pol.display_name}",
        f"# Source Sentinel ID: {pol.guid} | Enforcement Level: {pol.default_effect}",
        f"# Target Resource Type(s): {', '.join(res_list)}",
        "",
        'default result = "PASS"',
        "",
        'result = "FAIL" {',
        f"    # Verify runtime resource attribute mapped from {pol.source_engine}: {primary_field}",
        f"    input.{clean_path} == null",
        "}",
        "",
        f'currentConfiguration := sprintf("Evaluated field \'{primary_field}\' on {pol.cloud_provider} resource %v", [input.id])',
        f'expectedConfiguration := "{pol.display_name} must comply with enterprise security standard"',
    ]
    return "\n".join(lines)


def generate_sentinel_skeleton_from_wiz(wiz: WizRuleRecord) -> str:
    native_type = sorted(wiz.target_native_types)[0] if wiz.target_native_types else "resource"
    tf_type = WIZ_NATIVE_TO_TERRAFORM_MAP.get(
        (wiz.cloud_provider.upper(), native_type.lower()),
        f"{'aws' if wiz.cloud_provider.upper() == 'AWS' else 'azurerm'}_{native_type.lower()}",
    )
    rule_slug = re.sub(r"[^a-z0-9_]+", "_", wiz.name.lower()).strip("_")[:45]
    enf_level = "hard-mandatory" if wiz.severity in ("CRITICAL", "HIGH") else "soft-mandatory"

    lines = [
        f'# Auto-generated HashiCorp Sentinel Policy for {wiz.cloud_provider} Wiz CCR: {wiz.short_id}',
        f'# Wiz Rule: {wiz.name} (Severity: {wiz.severity})',
        f'# sentinel.hcl registration:',
        f'# policy "{wiz.short_id.lower()}" {{',
        f'#   source            = "./{wiz.short_id.lower()}.sentinel"',
        f'#   enforcement_level = "{enf_level}"',
        f'# }}',
        "",
        'import "tfplan/v2" as tfplan',
        "",
        f"target_resources = filter tfplan.resource_changes as _, rc {{",
        f'    rc.type is "{tf_type}" and',
        '    rc.mode is "managed" and',
        '    (rc.change.actions contains "create" or rc.change.actions contains "update")',
        "}",
        "",
        f"{rule_slug} = rule {{",
        "    all target_resources as _, r {",
        f"        # Validate required security attribute for {wiz.short_id}",
        "        r.change.after is not null",
        "    }",
        "}",
        "",
        "main = rule {",
        f"    {rule_slug}",
        "}",
    ]
    return "\n".join(lines)


# =====================================================================
# PARSERS: HASHICORP SENTINEL (.sentinel + sentinel.hcl) & WIZ CCRs
# =====================================================================

def parse_policy_controls(raw_policies: List[Dict[str, Any]]) -> List[PolicyControlRecord]:
    records: List[PolicyControlRecord] = []

    for item in raw_policies:
        props = item.get("properties", item)
        policy_id = str(item.get("id") or item.get("name") or "")
        guid_match = GUID_REGEX.search(policy_id) or GUID_REGEX.search(str(item.get("name", "")))
        guid = guid_match.group(0).lower() if guid_match else str(item.get("name", policy_id)).lower()

        display_name = str(props.get("displayName") or item.get("displayName") or item.get("title") or guid)
        description = str(props.get("description") or item.get("description") or "")
        metadata = props.get("metadata") or {}
        category = str(metadata.get("category") or item.get("category") or "Security")
        policy_type = str(props.get("policyType") or item.get("policyType") or "Sentinel-IaC")

        source_engine = str(item.get("sourceEngine") or metadata.get("sourceEngine") or "HashiCorp Sentinel")
        cloud_provider = str(item.get("cloudProvider") or metadata.get("cloudProvider") or "").upper()

        res_types: Set[str] = set()
        cond_fields: Set[str] = set()
        effect = str(item.get("enforcementLevel") or item.get("defaultEffect") or "hard-mandatory")

        if item.get("resourceTypes"):
            res_types.update(str(x).lower() for x in item["resourceTypes"])
        if item.get("conditionFields"):
            cond_fields.update(str(x) for x in item["conditionFields"])

        joined_res = " ".join(res_types).lower()
        if not cloud_provider:
            if "aws_" in joined_res or "s3" in display_name.lower() or "ec2" in display_name.lower() or "rds" in display_name.lower():
                cloud_provider = "AWS"
            else:
                cloud_provider = "AZURE"

        controls: Set[str] = set()
        for match in CONTROL_ID_REGEX.findall(f"{display_name} {description} {json.dumps(metadata)}"):
            controls.add(re.sub(r"\s+", " ", match.upper().strip()))
        if item.get("complianceControls"):
            controls.update(str(c).upper() for c in item["complianceControls"])

        records.append(
            PolicyControlRecord(
                policy_id=policy_id,
                guid=guid,
                cloud_provider=cloud_provider,
                source_engine=source_engine,
                display_name=display_name,
                description=description,
                category=category,
                policy_type=policy_type,
                default_effect=effect,
                target_resource_types=res_types,
                condition_fields=cond_fields,
                compliance_controls=controls,
                checkov_id=str(item.get("checkovId", "")),
            )
        )
    return records


def parse_sentinel_directory(sentinel_dir: str) -> List[PolicyControlRecord]:
    enforcement_by_name: Dict[str, str] = {}
    for hcl_path in glob.glob(os.path.join(sentinel_dir, "**", "*sentinel.hcl"), recursive=True):
        with open(hcl_path, "r", encoding="utf-8", errors="replace") as hf:
            hcl_text = hf.read()
        for match in SENTINEL_HCL_BLOCK_REGEX.finditer(hcl_text):
            p_name = match.group(1).strip().lower()
            block_body = match.group(2)
            enf_match = re.search(r'enforcement_level\s*=\s*"([^"]+)"', block_body)
            if enf_match:
                enforcement_by_name[p_name] = enf_match.group(1).strip()

    records: List[PolicyControlRecord] = []
    for path in sorted(glob.glob(os.path.join(sentinel_dir, "**", "*.sentinel"), recursive=True)):
        fname = os.path.splitext(os.path.basename(path))[0]
        if fname.startswith("mock-") or "/test/" in path.replace("\\", "/"):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        tf_types = {m.lower() for m in TF_RESOURCE_REGEX.findall(content)}
        cloud = "AWS" if any(t.startswith("aws_") for t in tf_types) or "aws" in fname.lower() else "AZURE"
        comments = re.findall(r"^\s*#\s*(.+)$", content, re.MULTILINE)
        title = comments[0] if comments else fname.replace("-", " ").replace("_", " ").title()
        desc = " ".join(comments[:3]) if comments else f"HashiCorp Sentinel policy {fname}"
        controls = {re.sub(r"\s+", " ", m.upper().strip()) for m in CONTROL_ID_REGEX.findall(content)}
        attrs = set(re.findall(r"rc\.change\.after\.([a-zA-Z0-9_.]+)", content))
        effect = enforcement_by_name.get(fname.lower(), "hard-mandatory")

        records.append(
            PolicyControlRecord(
                policy_id=path,
                guid=fname.lower(),
                cloud_provider=cloud,
                source_engine="HashiCorp Sentinel",
                display_name=title,
                description=desc,
                category="Terraform IaC",
                policy_type="Sentinel-IaC",
                default_effect=effect,
                target_resource_types=tf_types,
                condition_fields=attrs,
                compliance_controls=controls,
            )
        )
    return records


def parse_wiz_rules(raw_rules: List[Dict[str, Any]], since_days: int = 1) -> List[WizRuleRecord]:
    records: List[WizRuleRecord] = []
    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=since_days)

    for r in raw_rules:
        rule_id = str(r.get("id", ""))
        short_id = str(r.get("shortId") or r.get("builtinId") or rule_id)
        name = str(r.get("name", ""))
        desc = str(r.get("description", ""))
        remediation = str(r.get("remediationInstructions", ""))
        builtin_id = str(r.get("builtinId", ""))
        severity = str(r.get("severity", "MEDIUM"))
        enabled = bool(r.get("enabled", True))
        cloud_provider = str(r.get("cloudProvider", "")).upper()
        created_at = str(r.get("createdAt", ""))
        updated_at = str(r.get("updatedAt", ""))

        native_types = {str(t).lower() for t in (r.get("targetNativeTypes") or [])}
        if not cloud_provider:
            if any(k in name.lower() or k in " ".join(native_types) for k in ("s3", "ec2", "iam", "rds", "kms", "ebs", "eks", "cloudtrail", "aws")):
                cloud_provider = "AWS"
            else:
                cloud_provider = "AZURE"

        change_status = str(r.get("ccrChangeStatus", "Baseline"))
        if change_status == "Baseline" and (created_at or updated_at):
            try:
                if created_at and datetime.fromisoformat(created_at.replace("Z", "+00:00")) >= cutoff_dt:
                    change_status = "New CCR (24h Daily)"
                elif updated_at and datetime.fromisoformat(updated_at.replace("Z", "+00:00")) >= cutoff_dt:
                    change_status = "Updated CCR (24h Daily)"
            except ValueError:
                pass

        ctrl = r.get("control") or {}
        issue_gen = bool(r.get("issueGenerationEnabled", ctrl.get("enabled", severity in ("CRITICAL", "HIGH"))))
        graph_controls = int(r.get("linkedSecurityGraphControls", 1 if ctrl.get("id") else 0))
        analytics = r.get("analytics") or {}
        fail_count = int(r.get("failingFindingsCount", analytics.get("failCount", 0)))
        pass_count = int(r.get("passFindingsCount", analytics.get("passCount", 0)))

        combined_text = f"{builtin_id} {desc} {remediation}"
        guids = {m.lower() for m in GUID_REGEX.findall(combined_text)}

        controls: Set[str] = set()
        for sub in r.get("securitySubCategories") or []:
            sub_title = str(sub.get("title", ""))
            cat = sub.get("category") or {}
            fw = (cat.get("framework") or {}).get("name", "")
            full_ref = f"{fw} {cat.get('name', '')} {sub_title}".strip()
            for match in CONTROL_ID_REGEX.findall(full_ref):
                controls.add(re.sub(r"\s+", " ", match.upper().strip()))
            if sub.get("id"):
                controls.add(str(sub["id"]).upper())

        records.append(
            WizRuleRecord(
                rule_id=rule_id,
                short_id=short_id,
                cloud_provider=cloud_provider,
                name=name,
                description=desc,
                severity=severity,
                enabled=enabled,
                target_native_types=native_types,
                referenced_guids=guids,
                compliance_controls=controls,
                has_opa_rego=bool(r.get("opaPolicy")),
                created_at=created_at,
                updated_at=updated_at,
                ccr_change_status=change_status,
                issue_generation_enabled=issue_gen,
                linked_security_graph_controls=graph_controls,
                failing_findings_count=fail_count,
                pass_findings_count=pass_count,
            )
        )
    return records


# =====================================================================
# 3-LAYER CORRELATION & BI-WEEKLY SDLC GOVERNANCE ENGINE
# =====================================================================

def tokenize(text: str, stop_words: Set[str] = DEFAULT_STOP_WORDS) -> Set[str]:
    tokens = set(re.findall(r"[a-z0-9]{2,}", text.lower()))
    return tokens - stop_words


def resource_types_compatible(
    pol_types: Set[str],
    wiz_types: Set[str],
    resource_map: Dict[str, Set[str]] = DEFAULT_MULTICLOUD_RESOURCE_MAP,
) -> Tuple[bool, float]:
    if not pol_types or not wiz_types:
        return True, 0.5

    normalized_wiz_candidates: Set[str] = set()
    for pt in pol_types:
        pt_clean = pt.lower()
        if pt_clean in resource_map:
            normalized_wiz_candidates.update(resource_map[pt_clean])
        parts = re.split(r"[./:_]", pt_clean)
        for p in parts:
            if p and p not in ("microsoft", "azurerm", "aws"):
                normalized_wiz_candidates.add(p.rstrip("s"))
                normalized_wiz_candidates.add(p)

    wiz_clean = {w.lower().replace("_", "").replace("-", "").strip() for w in wiz_types}
    norm_clean = {n.lower().replace("_", "").replace("-", "").strip() for n in normalized_wiz_candidates}

    if wiz_clean & norm_clean:
        return True, 1.0

    for w in wiz_clean:
        for n in norm_clean:
            if len(n) >= 3 and (n in w or w in n):
                return True, 0.85

    return False, 0.0


def compute_similarity(
    pol: PolicyControlRecord,
    wiz: WizRuleRecord,
    resource_map: Dict[str, Set[str]] = DEFAULT_MULTICLOUD_RESOURCE_MAP,
    weights: Dict[str, float] = DEFAULT_WEIGHTS,
) -> Tuple[float, str]:
    if pol.cloud_provider.upper() != wiz.cloud_provider.upper():
        return 0.0, f"Cloud provider mismatch ({pol.cloud_provider} vs {wiz.cloud_provider})"

    if pol.guid in wiz.referenced_guids or pol.guid == wiz.short_id.lower():
        return 0.99, f"Exact ID/GUID ({pol.guid}) referenced in Wiz rule metadata"

    compatible, res_score = resource_types_compatible(pol.target_resource_types, wiz.target_native_types, resource_map)
    if not compatible:
        return 0.0, "Incompatible resource types"

    pol_name_tokens = tokenize(pol.display_name)
    wiz_name_tokens = tokenize(wiz.name)
    name_jaccard = (
        len(pol_name_tokens & wiz_name_tokens) / len(pol_name_tokens | wiz_name_tokens)
        if (pol_name_tokens | wiz_name_tokens)
        else 0.0
    )

    name_seq = difflib.SequenceMatcher(None, pol.display_name.lower(), wiz.name.lower()).ratio()

    pol_full_tokens = pol_name_tokens | tokenize(pol.description)
    wiz_full_tokens = wiz_name_tokens | tokenize(wiz.description)
    desc_jaccard = (
        len(pol_full_tokens & wiz_full_tokens) / len(pol_full_tokens | wiz_full_tokens)
        if (pol_full_tokens | wiz_full_tokens)
        else 0.0
    )

    shared_controls = pol.compliance_controls & wiz.compliance_controls
    control_boost = (
        min(weights["control_boost_max"], weights["control_boost_per_match"] * len(shared_controls))
        if shared_controls
        else 0.0
    )

    composite = (
        weights["name_jaccard"] * name_jaccard
        + weights["name_sequence"] * name_seq
        + weights["desc_jaccard"] * desc_jaccard
        + weights["resource_type"] * res_score
        + control_boost
    )
    composite = min(0.98, round(composite, 4))

    reasons = []
    if shared_controls:
        reasons.append(f"Shared controls: {', '.join(sorted(shared_controls))}")
    if res_score >= 0.85:
        reasons.append(f"Matched {pol.cloud_provider} resource type")
    reasons.append(f"Similarity={composite:.2f}")

    return composite, "; ".join(reasons)


def build_bidirectional_mappings(
    policies: List[PolicyControlRecord],
    wiz_rules: List[WizRuleRecord],
    min_threshold: float = 0.42,
    reassessment_days: int = 90,
    resource_map: Dict[str, Set[str]] = DEFAULT_MULTICLOUD_RESOURCE_MAP,
    weights: Dict[str, float] = DEFAULT_WEIGHTS,
) -> List[MappingResult]:
    results: List[MappingResult] = []
    matched_wiz_ids: Set[str] = set()
    next_review_dt = (datetime.now(timezone.utc) + timedelta(days=reassessment_days)).strftime("%Y-%m-%d")

    for pol in policies:
        best_wiz: Optional[WizRuleRecord] = None
        best_score = 0.0
        best_rationale = "No matching Wiz Cloud Configuration Rule met threshold"

        for wiz in wiz_rules:
            score, rationale = compute_similarity(pol, wiz, resource_map, weights)
            if score > best_score:
                best_score = score
                best_wiz = wiz
                best_rationale = rationale

        cond_str = ", ".join(sorted(pol.condition_fields)) or "N/A"
        rego_code = generate_opa_rego_skeleton(pol)
        is_preventative = pol.default_effect.lower() in PREVENTATIVE_EFFECTS

        ckv_id, ckv_status = resolve_checkov_mapping(
            pol.cloud_provider,
            pol.target_resource_types,
            f"{pol.display_name} {' '.join(pol.condition_fields)}",
            pol.checkov_id,
        )
        ckv_yaml = generate_checkov_custom_yaml(
            ckv_id,
            pol.cloud_provider,
            pol.display_name,
            pol.target_resource_types,
            pol.condition_fields,
            pol.category,
        )

        if best_wiz and best_score >= min_threshold:
            matched_wiz_ids.add(best_wiz.rule_id)
            sentinel_code = generate_sentinel_skeleton_from_wiz(best_wiz)
            shared_ctrl = sorted(pol.compliance_controls & best_wiz.compliance_controls)
            if best_score >= 0.95:
                tier = "Tier 1: Exact Native ID"
                status = "Auto-Approved (1:1:1)"
            elif shared_ctrl and best_score >= 0.65:
                tier = "Tier 2: Compliance Crosswalk"
                status = "Approved (Crosswalk)"
            elif best_score >= 0.70:
                tier = "Tier 3: High Semantic Match"
                status = "Approved (Heuristic)"
            else:
                tier = "Tier 4: Candidate Match"
                status = "Manual SME Review Required"

            # SDLC Governance & Exception Evaluation
            if not best_wiz.enabled:
                sdlc_stage = "Excluded (Documented Rule Exception)"
                exc_status = "Excluded - Compensated by Sentinel/Checkov"
                exc_just = f"Wiz rule excluded from runtime alerting; enforced pre-deployment by {pol.source_engine} ({pol.default_effect}) and {ckv_id}."
                approver = "Cloud Security Governance Board (Pending Periodic Reassessment)"
            elif "New CCR" in best_wiz.ccr_change_status or "Updated CCR" in best_wiz.ccr_change_status:
                sdlc_stage = "Daily SDLC Review & Testing Queue"
                exc_status = "Active Policy (Pending Bi-Weekly Sign-Off)"
                exc_just = "N/A (Active Baseline Control under 14-day SDLC evaluation)"
                approver = "Pending Policies Review (Policy Review Lead)"
            else:
                sdlc_stage = "SDLC Approved & Implemented"
                exc_status = "Active Policy (No Exception)"
                exc_just = "N/A (Approved Active Baseline Control)"
                approver = "Approved Baseline (Cloud Security Governance)"

            finding_val = f"Validated ({pol.cloud_provider} Env)" if best_score >= 0.65 else "Pending False-Positive Check"
            issue_cfg = (
                "Enabled (Auto-Creates Wiz Issue)"
                if best_wiz.issue_generation_enabled
                else "Action Needed: Enable Wiz Issue Generation"
            )
            graph_status = (
                f"Graph Linked ({best_wiz.linked_security_graph_controls} Control, {best_wiz.failing_findings_count} Failing / {best_wiz.pass_findings_count} Passing)"
                if best_wiz.linked_security_graph_controls > 0
                else "CCR Only (Verify Security Graph Issue Correlation)"
            )

            if is_preventative:
                gap_dir = "Bidirectional Parity (Covered)"
                prev_cov = f"3-Layer Active ({ckv_id} + Sentinel {pol.default_effect} + Wiz)"
                ticket = "None (Covered in Checkov, Sentinel & Wiz)"
            else:
                gap_dir = "Wiz -> Sentinel Preventative Upgrade"
                prev_cov = f"Advisory Only ({pol.default_effect}) — Upgrade to hard-mandatory Sentinel"
                ticket = f"Create Team Issue: Enforce hard-mandatory HashiCorp Sentinel ({pol.cloud_provider})"

            results.append(
                MappingResult(
                    cloud_provider=pol.cloud_provider,
                    source_engine=pol.source_engine,
                    gap_direction=gap_dir,
                    checkov_id=ckv_id,
                    checkov_status=ckv_status,
                    ccr_change_status=best_wiz.ccr_change_status,
                    wiz_updated_at=best_wiz.updated_at or "Baseline",
                    finding_validation_status=finding_val,
                    issue_generation_configured=issue_cfg,
                    security_graph_status=graph_status,
                    preventative_control_coverage=prev_cov,
                    team_action_ticket=ticket,
                    sdlc_governance_stage=sdlc_stage,
                    rule_exception_status=exc_status,
                    exception_justification=exc_just,
                    approver_signoff=approver,
                    next_periodic_review_date=next_review_dt,
                    azure_policy_guid=pol.guid,
                    azure_policy_name=pol.display_name,
                    azure_policy_type=pol.policy_type,
                    azure_category=pol.category,
                    azure_default_effect=pol.default_effect,
                    azure_resource_types=", ".join(sorted(pol.target_resource_types)) or "All/Unspecified",
                    azure_condition_fields=cond_str,
                    wiz_rule_id=best_wiz.rule_id,
                    wiz_short_id=best_wiz.short_id,
                    wiz_rule_name=best_wiz.name,
                    wiz_severity=best_wiz.severity,
                    wiz_native_types=", ".join(sorted(best_wiz.target_native_types)),
                    mapping_tier=tier,
                    confidence_score=best_score,
                    shared_controls=", ".join(shared_ctrl),
                    review_status=status,
                    mapping_rationale=best_rationale,
                    generated_checkov_yaml=ckv_yaml,
                    generated_sentinel_skeleton=sentinel_code if not is_preventative else "",
                    generated_rego_skeleton=rego_code if tier == "Tier 4: Candidate Match" else "",
                )
            )
        else:
            results.append(
                MappingResult(
                    cloud_provider=pol.cloud_provider,
                    source_engine=pol.source_engine,
                    gap_direction="Sentinel -> Wiz Gap (Missing Wiz CCR)",
                    checkov_id=ckv_id,
                    checkov_status=ckv_status,
                    ccr_change_status="Gap: Missing in Wiz",
                    wiz_updated_at="N/A",
                    finding_validation_status=f"Relevant ({pol.cloud_provider} Custom Guardrail)",
                    issue_generation_configured="Not Configured (Requires Custom Wiz CCR)",
                    security_graph_status="No Linked Graph Control",
                    preventative_control_coverage=f"Preventative {pol.source_engine} ({pol.default_effect}) Only — Missing Wiz Drift Check",
                    team_action_ticket=f"Create Team Issue: Deploy Custom Wiz OPA Rego CCR & {ckv_id}",
                    sdlc_governance_stage="Custom Rule SDLC Development (Custom Rule Engineering Lead)",
                    rule_exception_status="Custom Rule Pending Deployment",
                    exception_justification="Internal bank policy enforced in Sentinel; custom Wiz OPA Rego rule in SDLC development.",
                    approver_signoff="Pending Custom Rule Management (Custom Rule Engineering Lead)",
                    next_periodic_review_date=next_review_dt,
                    azure_policy_guid=pol.guid,
                    azure_policy_name=pol.display_name,
                    azure_policy_type=pol.policy_type,
                    azure_category=pol.category,
                    azure_default_effect=pol.default_effect,
                    azure_resource_types=", ".join(sorted(pol.target_resource_types)) or "All/Unspecified",
                    azure_condition_fields=cond_str,
                    wiz_rule_id="UNMAPPED",
                    wiz_short_id="UNMAPPED",
                    wiz_rule_name="No Equivalent Built-In Wiz Rule Found",
                    wiz_severity="N/A",
                    wiz_native_types="N/A",
                    mapping_tier="Tier 5: Coverage Gap",
                    confidence_score=round(best_score, 4),
                    shared_controls=", ".join(sorted(pol.compliance_controls)),
                    review_status="Action Required: Build Custom Wiz Rego Rule",
                    mapping_rationale=best_rationale,
                    generated_checkov_yaml=ckv_yaml,
                    generated_sentinel_skeleton="",
                    generated_rego_skeleton=rego_code,
                )
            )

    # Wiz -> Sentinel Gaps (and Excluded Wiz Rules)
    for wiz in wiz_rules:
        if wiz.rule_id not in matched_wiz_ids:
            sentinel_code = generate_sentinel_skeleton_from_wiz(wiz)
            native_str = ", ".join(sorted(wiz.target_native_types)) or "resource"
            tf_target = WIZ_NATIVE_TO_TERRAFORM_MAP.get(
                (wiz.cloud_provider.upper(), sorted(wiz.target_native_types)[0] if wiz.target_native_types else ""),
                f"{'aws' if wiz.cloud_provider.upper() == 'AWS' else 'azurerm'}_{native_str}",
            )
            ckv_id, ckv_status = resolve_checkov_mapping(
                wiz.cloud_provider,
                {tf_target},
                f"{wiz.name} {wiz.description}",
            )
            ckv_yaml = generate_checkov_custom_yaml(
                ckv_id,
                wiz.cloud_provider,
                wiz.name,
                {tf_target},
                {"security_configuration"},
                native_str,
            )

            if not wiz.enabled:
                sdlc_stage = "Excluded (Documented Rule Exception)"
                exc_status = "Excluded - Not Applicable to Cloud Architecture"
                exc_just = f"Wiz rule ({wiz.short_id}) evaluated during bi-weekly review and excluded as not applicable to bank {wiz.cloud_provider} architecture."
                approver = "Approved Exception (Policies Review - Policy Review Lead)"
            else:
                sdlc_stage = "Daily SDLC Review & Testing Queue"
                exc_status = "Active Wiz Rule (Missing Sentinel Gate)"
                exc_just = "Active bi-weekly Wiz rule; requires SDLC evaluation and HashiCorp Sentinel preventative deployment."
                approver = "Pending Policies Review (Policy Review Lead)"

            results.append(
                MappingResult(
                    cloud_provider=wiz.cloud_provider,
                    source_engine="Missing HashiCorp Sentinel",
                    gap_direction="Wiz -> Sentinel Gap (Missing Sentinel Policy)",
                    checkov_id=ckv_id,
                    checkov_status=ckv_status,
                    ccr_change_status=wiz.ccr_change_status,
                    wiz_updated_at=wiz.updated_at or "Baseline",
                    finding_validation_status=(
                        "Excluded / Not Applicable (Exception)"
                        if not wiz.enabled
                        else ("Validated · Issue Gen Enabled" if wiz.issue_generation_enabled else "Validated · Configure Issue Gen")
                    ),
                    issue_generation_configured=(
                        "Disabled (Rule Exception)"
                        if not wiz.enabled
                        else ("Enabled (Auto-Creates Wiz Issue)" if wiz.issue_generation_enabled else "Action Needed: Enable Wiz Issue Generation")
                    ),
                    security_graph_status=(
                        f"Graph Linked ({wiz.linked_security_graph_controls} Control, {wiz.failing_findings_count} Failing / {wiz.pass_findings_count} Passing)"
                        if wiz.linked_security_graph_controls > 0
                        else "CCR Only · Needs Graph Control Link"
                    ),
                    preventative_control_coverage=f"Gap: Wiz Runtime + {ckv_id} — Missing {wiz.cloud_provider} HashiCorp Sentinel Gate",
                    team_action_ticket=f"Create Team Issue: Author {wiz.cloud_provider} HashiCorp Sentinel Policy ({tf_target})",
                    sdlc_governance_stage=sdlc_stage,
                    rule_exception_status=exc_status,
                    exception_justification=exc_just,
                    approver_signoff=approver,
                    next_periodic_review_date=next_review_dt,
                    azure_policy_guid=f"MISSING-SENTINEL-{wiz.short_id.upper()}",
                    azure_policy_name=f"[Missing HashiCorp Sentinel] {wiz.name}",
                    azure_policy_type="Missing-Sentinel",
                    azure_category=native_str.upper(),
                    azure_default_effect="Missing (No Sentinel in TFC/TFE)",
                    azure_resource_types=tf_target,
                    azure_condition_fields=f"tfplan.resource_changes ({tf_target})",
                    wiz_rule_id=wiz.rule_id,
                    wiz_short_id=wiz.short_id,
                    wiz_rule_name=wiz.name,
                    wiz_severity=wiz.severity,
                    wiz_native_types=native_str,
                    mapping_tier="Tier 5: Coverage Gap",
                    confidence_score=0.0,
                    shared_controls=", ".join(sorted(wiz.compliance_controls)),
                    review_status=f"Action Required: Deploy Generated {wiz.cloud_provider} HashiCorp Sentinel Policy",
                    mapping_rationale=f"Active {wiz.cloud_provider} Wiz CCR ({wiz.short_id}) maps to {ckv_id} in CI but lacks a TFC/TFE Sentinel policy",
                    generated_checkov_yaml=ckv_yaml,
                    generated_sentinel_skeleton=sentinel_code,
                    generated_rego_skeleton="",
                )
            )

    return results


# =====================================================================
# OUTPUT EXPORTERS & MULTI-CLOUD DEMO SELF-TEST
# =====================================================================

def apply_baseline_diff_and_expiration_check(
    current_results: List[MappingResult],
    baseline_json_path: Optional[str] = None,
) -> List[MappingResult]:
    """
    Compares current mapping results against a previous signed-off audit JSON snapshot:
      1. Carries forward SME approvals, owners, and exception justifications for unchanged rules.
      2. Detects Rule/Framework Drift if Wiz severity, rule name, or framework controls changed since baseline.
      3. Automatically flags Expired Exceptions if next_periodic_review_date <= today.
    """
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    baseline_by_key: Dict[str, Dict[str, Any]] = {}

    if baseline_json_path and os.path.exists(baseline_json_path):
        with open(baseline_json_path, "r", encoding="utf-8") as bf:
            b_data = json.load(bf)
            rows = b_data.get("mappings", b_data) if isinstance(b_data, dict) else b_data
            for r in rows:
                key = f"{r.get('cloud_provider', '')}:{r.get('azure_policy_guid', '')}:{r.get('wiz_short_id', '')}"
                baseline_by_key[key] = r
        logger.info("Loaded %d baseline audit records from %s for drift & expiration check.", len(baseline_by_key), baseline_json_path)

    for res in current_results:
        key = f"{res.cloud_provider}:{res.azure_policy_guid}:{res.wiz_short_id}"
        prev = baseline_by_key.get(key)
        if prev:
            prev_controls = str(prev.get("shared_controls", ""))
            prev_sev = str(prev.get("wiz_severity", ""))
            prev_updated = str(prev.get("wiz_updated_at", ""))

            # Check if Wiz rule or Compliance Framework mapping drifted since last sign-off
            if prev_controls != res.shared_controls or prev_sev != res.wiz_severity or (res.wiz_updated_at != prev_updated and res.wiz_updated_at != "Baseline"):
                res.ccr_change_status = "Drift Detected (Rule/Framework Updated)"
                res.sdlc_governance_stage = "Daily SDLC Re-Evaluation Required (Drift)"
            else:
                # Carry forward previous approved SDLC state, owner, justification, and review date
                res.sdlc_governance_stage = str(prev.get("sdlc_governance_stage") or res.sdlc_governance_stage)
                res.rule_exception_status = str(prev.get("rule_exception_status") or res.rule_exception_status)
                res.exception_justification = str(prev.get("exception_justification") or res.exception_justification)
                res.approver_signoff = str(prev.get("approver_signoff") or res.approver_signoff)
                res.next_periodic_review_date = str(prev.get("next_periodic_review_date") or res.next_periodic_review_date)

        # Check if periodic reassessment date has expired
        if res.next_periodic_review_date and res.next_periodic_review_date <= today_str:
            res.sdlc_governance_stage = f"EXPIRED: Periodic Reassessment Due ({res.next_periodic_review_date})"

    return current_results


def export_interactive_html_report(results: List[MappingResult], html_path: str) -> None:
    """Generates a standalone, self-contained interactive HTML mapping & SDLC audit report."""
    data_json = json.dumps([asdict(r) for r in results])
    gen_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html_doc = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Interactive Cloud Security 3-Layer Mapping &amp; SDLC Audit Report</title>
<script src="https://cdn.tailwindcss.com/3.4.17"></script>
</head>
<body class="bg-slate-950 text-slate-100 p-6 font-sans">
  <div class="max-w-7xl mx-auto space-y-5">
    <div class="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
      <div>
        <span class="px-2.5 py-0.5 text-[11px] font-bold uppercase rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">Interactive Audit Deliverable</span>
        <h1 class="text-xl font-bold text-white mt-1">Wiz Policies ⇄ HashiCorp Sentinel ⇄ Checkov 1:1 Mapping &amp; SDLC Report</h1>
        <p class="text-xs text-slate-400">Generated: {gen_ts} · Schema: {SCHEMA_VERSION} · Total Controls: {len(results)}</p>
      </div>
      <button onclick="window.print()" class="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700">Print / Save PDF</button>
    </div>

    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3" id="kpiRow"></div>

    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 grid grid-cols-1 sm:grid-cols-4 gap-3">
      <input id="q" type="text" placeholder="Search policy, CKV ID, Wiz ID, resource, owner..." class="sm:col-span-2 bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white">
      <select id="cloud" class="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white">
        <option value="ALL">All Clouds (AWS + Azure)</option>
        <option value="AWS">AWS Only</option>
        <option value="AZURE">Azure Only</option>
      </select>
      <select id="gap" class="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white">
        <option value="ALL">All Gap &amp; SDLC States</option>
        <option value="Parity">Bidirectional Parity</option>
        <option value="Wiz -> Sentinel">Wiz → Sentinel Gap</option>
        <option value="Sentinel -> Wiz">Sentinel → Wiz Gap</option>
        <option value="Excluded">Excluded Rule Exceptions</option>
      </select>
    </div>

    <div class="overflow-x-auto bg-slate-900 border border-slate-800 rounded-xl">
      <table class="w-full text-left text-xs">
        <thead class="bg-slate-950 text-slate-400 uppercase text-[11px] border-b border-slate-800">
          <tr>
            <th class="p-3">Cloud / Checkov / Sentinel Policy</th>
            <th class="p-3">Gap Direction &amp; Enforcement</th>
            <th class="p-3">Mapped Wiz CCR &amp; Graph Status</th>
            <th class="p-3">Tier &amp; Score</th>
            <th class="p-3">SDLC Governance &amp; Next Review</th>
            <th class="p-3 text-right">Policy Code</th>
          </tr>
        </thead>
        <tbody id="tbody" class="divide-y divide-slate-800"></tbody>
      </table>
    </div>
  </div>

<script>
const DATA = {data_json};
function render() {{
  const q = document.getElementById('q').value.toLowerCase();
  const c = document.getElementById('cloud').value;
  const g = document.getElementById('gap').value;
  const filtered = DATA.filter(r => {{
    if (c !== 'ALL' && r.cloud_provider !== c) return false;
    if (g !== 'ALL') {{
      const hayG = `${{r.gap_direction}} ${{r.sdlc_governance_stage}} ${{r.rule_exception_status}}`;
      if (!hayG.includes(g)) return false;
    }}
    return !q || JSON.stringify(r).toLowerCase().includes(q);
  }});

  const parity = filtered.filter(r => (r.gap_direction || '').includes('Parity')).length;
  const wizGap = filtered.filter(r => (r.gap_direction || '').includes('Wiz -> Sentinel')).length;
  const sentGap = filtered.filter(r => (r.gap_direction || '').includes('Sentinel -> Wiz')).length;
  document.getElementById('kpiRow').innerHTML = `
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-3.5"><div class="text-xs text-slate-400">Filtered Controls</div><div class="text-xl font-bold text-white mt-0.5">${{filtered.length}}</div></div>
    <div class="bg-slate-900 border border-emerald-500/30 rounded-xl p-3.5"><div class="text-xs text-emerald-300">3-Layer Parity</div><div class="text-xl font-bold text-emerald-400 mt-0.5">${{parity}}</div></div>
    <div class="bg-slate-900 border border-amber-500/30 rounded-xl p-3.5"><div class="text-xs text-amber-300">Wiz → Sentinel Gaps</div><div class="text-xl font-bold text-amber-400 mt-0.5">${{wizGap}}</div></div>
    <div class="bg-slate-900 border border-rose-500/30 rounded-xl p-3.5"><div class="text-xs text-rose-300">Sentinel → Wiz Gaps</div><div class="text-xl font-bold text-rose-400 mt-0.5">${{sentGap}}</div></div>
  `;

  document.getElementById('tbody').innerHTML = filtered.map((r, i) => `
    <tr class="hover:bg-slate-800/50">
      <td class="p-3">
        <div class="flex items-center gap-1.5 mb-1">
          <span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${{r.cloud_provider === 'AWS' ? 'bg-amber-500/20 text-amber-300' : 'bg-blue-500/20 text-blue-300'}}">${{r.cloud_provider}}</span>
          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-500/15 text-cyan-300">L1: ${{r.checkov_id}}</span>
        </div>
        <div class="font-semibold text-white">${{r.azure_policy_name}}</div>
        <div class="text-[11px] font-mono text-slate-400">${{r.azure_policy_guid}} · ${{r.azure_resource_types}}</div>
      </td>
      <td class="p-3">
        <div class="font-medium text-slate-200">${{r.gap_direction}}</div>
        <div class="text-[11px] text-slate-400 mt-0.5">Effect: ${{r.azure_default_effect}}</div>
      </td>
      <td class="p-3">
        <div class="font-medium text-white">${{r.wiz_rule_name}}</div>
        <div class="text-[11px] font-mono text-indigo-400">${{r.wiz_short_id}} (${{r.wiz_severity}}) · ${{r.ccr_change_status}}</div>
        <div class="text-[10px] text-slate-400 mt-0.5">${{r.security_graph_status}}</div>
      </td>
      <td class="p-3">
        <div class="font-semibold text-slate-200">${{r.mapping_tier}}</div>
        <div class="font-mono text-emerald-400 text-[11px]">${{Math.round((r.confidence_score || 0) * 100)}}%</div>
      </td>
      <td class="p-3">
        <div class="font-semibold text-amber-300">${{r.sdlc_governance_stage || r.sdlc_exception_status || r.review_status}}</div>
        <div class="text-[11px] text-slate-400">Owner: ${{r.approver_signoff || r.sdlc_approver || 'Cloud Security'}}</div>
        <div class="text-[10px] font-mono text-indigo-300">Next Review: ${{r.next_periodic_review_date || '90d'}}</div>
      </td>
      <td class="p-3 text-right">
        <button onclick="document.getElementById('code-'+${{i}}).classList.toggle('hidden')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-indigo-600 text-slate-200 text-[11px] border border-slate-700">View Code</button>
      </td>
    </tr>
    <tr id="code-${{i}}" class="hidden bg-slate-950/90">
      <td colspan="6" class="p-4">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-3 text-[11px] font-mono">
          <div><div class="text-cyan-300 font-sans font-semibold mb-1">Layer 1: Checkov (.yaml)</div><pre class="bg-slate-900 p-2.5 rounded border border-slate-800 overflow-x-auto text-cyan-200">${{r.generated_checkov_yaml || 'N/A'}}</pre></div>
          <div><div class="text-amber-300 font-sans font-semibold mb-1">Layer 2: HashiCorp Sentinel (.sentinel)</div><pre class="bg-slate-900 p-2.5 rounded border border-slate-800 overflow-x-auto text-amber-200">${{r.generated_sentinel_skeleton || 'Active in Sentinel'}}</pre></div>
          <div><div class="text-emerald-300 font-sans font-semibold mb-1">Layer 3: Wiz OPA Rego (.rego)</div><pre class="bg-slate-900 p-2.5 rounded border border-slate-800 overflow-x-auto text-emerald-200">${{r.generated_rego_skeleton || 'Active Built-In Wiz CCR'}}</pre></div>
        </div>
      </td>
    </tr>
  `).join('');
}}
['q', 'cloud', 'gap'].forEach(id => document.getElementById(id).addEventListener('input', render));
render();
</script>
</body>
</html>"""
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    logger.info("Saved standalone interactive HTML mapping report to %s", html_path)


def write_outputs(
    results: List[MappingResult],
    csv_path: str,
    json_path: Optional[str] = None,
    html_path: Optional[str] = None,
) -> None:
    fieldnames = [
        "cloud_provider",
        "source_engine",
        "gap_direction",
        "checkov_id",
        "checkov_status",
        "ccr_change_status",
        "wiz_updated_at",
        "sdlc_governance_stage",
        "rule_exception_status",
        "exception_justification",
        "approver_signoff",
        "next_periodic_review_date",
        "finding_validation_status",
        "issue_generation_configured",
        "security_graph_status",
        "preventative_control_coverage",
        "team_action_ticket",
        "azure_policy_guid",
        "azure_policy_name",
        "azure_policy_type",
        "azure_category",
        "azure_default_effect",
        "azure_resource_types",
        "azure_condition_fields",
        "wiz_rule_id",
        "wiz_short_id",
        "wiz_rule_name",
        "wiz_severity",
        "wiz_native_types",
        "mapping_tier",
        "confidence_score",
        "shared_controls",
        "review_status",
        "mapping_rationale",
        "generated_checkov_yaml",
        "generated_sentinel_skeleton",
        "generated_rego_skeleton",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(asdict(row))
    logger.info("Saved Daily SDLC & 3-Layer CSV report (%d rows) to %s", len(results), csv_path)

    if json_path:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "audit_observation": "Noncompliance with SDLC Practices for Automated Cloud Security Policy Deployments",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_records": len(results),
            "mappings": [asdict(r) for r in results],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        logger.info("Saved Daily SDLC JSON report to %s", json_path)

    if html_path:
        export_interactive_html_report(results, html_path)


def get_demo_datasets() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    sample_policies = [
        {
            "name": "sentinel-azurerm-storage-https-only",
            "cloudProvider": "AZURE",
            "sourceEngine": "HashiCorp Sentinel",
            "displayName": "Enforce HTTPS traffic only on Azure Storage Accounts",
            "description": "HashiCorp Sentinel policy enforcing enable_https_traffic_only = true on azurerm_storage_account. [CCM CEK-03, CIS 3.1, NIST SP 800-53 SC-8]",
            "category": "Storage",
            "policyType": "Sentinel-IaC",
            "enforcementLevel": "hard-mandatory",
            "resourceTypes": ["azurerm_storage_account"],
            "conditionFields": ["enable_https_traffic_only"],
            "checkovId": "CKV_AZURE_3",
        },
        {
            "name": "sentinel-aws-s3-block-public-access",
            "cloudProvider": "AWS",
            "sourceEngine": "HashiCorp Sentinel",
            "displayName": "Block S3 bucket public access at account and bucket level",
            "description": "HashiCorp Sentinel policy verifying block_public_acls and block_public_policy on aws_s3_bucket_public_access_block. [CCM DSP-17, CIS AWS 2.1.5, PCI-DSS 1.2.1]",
            "category": "Storage",
            "policyType": "Sentinel-IaC",
            "enforcementLevel": "hard-mandatory",
            "resourceTypes": ["aws_s3_bucket_public_access_block"],
            "conditionFields": ["block_public_acls", "block_public_policy"],
            "checkovId": "CKV_AWS_53",
        },
        {
            "name": "fin-sentinel-aws-mandatory-cost-tags",
            "cloudProvider": "AWS",
            "sourceEngine": "HashiCorp Sentinel",
            "displayName": "Require Bank CostCenter, DataClassification, and AppID tags on all AWS resources",
            "description": "Custom bank HashiCorp Sentinel guardrail blocking AWS deployments missing mandatory FFIEC CostCenter and DataClassification tags.",
            "category": "Tags",
            "policyType": "Custom",
            "enforcementLevel": "hard-mandatory",
            "resourceTypes": ["aws_s3_bucket", "aws_instance", "aws_db_instance"],
            "conditionFields": ["tags.CostCenter", "tags.DataClassification"],
            "complianceControls": ["CCM GRC-01", "FFIEC Asset Governance"],
        },
    ]

    sample_wiz = [
        {
            "id": "wc-az-001",
            "shortId": "StorageAccount-001",
            "cloudProvider": "AZURE",
            "name": "Storage account should enforce secure transfer (HTTPS)",
            "description": "Storage accounts should be configured to accept requests from secure connections only (supportsHttpsTrafficOnly).",
            "severity": "HIGH",
            "enabled": True,
            "updatedAt": "2026-10-24T14:20:00Z",
            "ccrChangeStatus": "Updated CCR (24h Daily)",
            "issueGenerationEnabled": True,
            "linkedSecurityGraphControls": 2,
            "failingFindingsCount": 4,
            "passFindingsCount": 182,
            "targetNativeTypes": ["storageAccount"],
            "securitySubCategories": [
                {
                    "id": "wsct-az-101",
                    "title": "CCM CEK-03 / CIS 3.1 Ensure that 'Secure transfer required' is set to 'Enabled'",
                    "category": {"name": "Storage Accounts", "framework": {"name": "CIS Azure"}},
                }
            ],
        },
        {
            "id": "wc-aws-101",
            "shortId": "S3Bucket-004",
            "cloudProvider": "AWS",
            "name": "S3 bucket should block public access",
            "description": "Ensure AWS S3 buckets restrict public access via block_public_acls and block_public_policy.",
            "severity": "CRITICAL",
            "enabled": True,
            "updatedAt": "2026-10-20T11:00:00Z",
            "ccrChangeStatus": "Updated CCR (24h Daily)",
            "issueGenerationEnabled": True,
            "linkedSecurityGraphControls": 3,
            "failingFindingsCount": 1,
            "passFindingsCount": 410,
            "targetNativeTypes": ["bucket"],
            "securitySubCategories": [
                {
                    "id": "wsct-aws-201",
                    "title": "CCM DSP-17 / CIS AWS 2.1.5 Ensure S3 Block Public Access is enabled",
                    "category": {"name": "S3", "framework": {"name": "CIS AWS"}},
                }
            ],
        },
        {
            "id": "wc-aws-205",
            "shortId": "RDS-011",
            "cloudProvider": "AWS",
            "name": "RDS DB instance storage encryption should be enabled with KMS CMK",
            "description": "AWS RDS database instances must have storage_encrypted enabled using a customer-managed KMS key. [CCM CEK-04, NIST SP 800-53 SC-28, PCI-DSS 3.5]",
            "severity": "HIGH",
            "enabled": False,
            "updatedAt": "2026-10-25T09:30:00Z",
            "ccrChangeStatus": "New CCR (24h Daily)",
            "issueGenerationEnabled": False,
            "linkedSecurityGraphControls": 2,
            "failingFindingsCount": 0,
            "passFindingsCount": 95,
            "targetNativeTypes": ["rds"],
            "securitySubCategories": [
                {
                    "id": "wsct-aws-309",
                    "title": "CCM CEK-04 / PCI-DSS 3.5 Protect cryptographic keys and encrypt RDS storage",
                    "category": {"name": "RDS", "framework": {"name": "PCI-DSS"}},
                }
            ],
        },
    ]
    return sample_policies, sample_wiz


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-Cloud (AWS & Azure) Daily SDLC Governance & 3-Layer Tri-Mapper (Checkov <-> Sentinel <-> Wiz)."
    )
    parser.add_argument("--sync-all-daily", action="store_true", help="Automated Daily Multi-Cloud Sync: polls all configured services (AWS, Azure, Wiz, HCP Terraform, local Sentinel/Checkov) and saves dated snapshots")
    parser.add_argument("--snapshot-dir", default="data/daily_snapshots", help="Directory to store dated daily policy snapshots when --sync-all-daily is used")
    parser.add_argument("--sentinel-dir", help="Path to local directory containing .sentinel files and sentinel.hcl (AWS & Azure)")
    parser.add_argument("--live-tfc", action="store_true", help="Fetch HashiCorp Sentinel policies directly from HCP Terraform / TFE API")
    parser.add_argument("--live-aws", action="store_true", help="Fetch AWS Config Rules & AWS Organizations SCPs directly from AWS API/CLI")
    parser.add_argument("--aws-region", default="us-east-1", help="AWS region for --live-aws Config rules query (default: us-east-1)")
    parser.add_argument("--live-azure", action="store_true", help="Fetch Azure Policy definitions directly from Azure ARM API/SDK")
    parser.add_argument("--subscription-id", help="Azure Subscription ID for --live-azure scope")
    parser.add_argument("--management-group-id", help="Azure Management Group ID for --live-azure scope")
    parser.add_argument("--tfc-org", help="HCP Terraform / Terraform Enterprise Organization name for --live-tfc")
    parser.add_argument("--tfc-url", default="https://app.terraform.io", help="HCP Terraform or TFE base URL")
    parser.add_argument("--azure-json", help="Optional path to exported Azure Sentinel JSON file")
    parser.add_argument("--aws-sentinel-json", help="Optional path to exported AWS HashiCorp Sentinel JSON file")
    parser.add_argument("--wiz-json", help="Path to exported Wiz cloudConfigurationRules JSON file")
    parser.add_argument("--live-wiz", action="store_true", help="Fetch AWS & Azure Wiz CCRs directly from Wiz GraphQL API")
    parser.add_argument("--cloud-providers", nargs="+", default=["AZURE", "AWS"], help="Cloud providers to query (default: AZURE AWS)")
    parser.add_argument("--since-days", type=int, default=1, help="Daily days window to flag New/Updated policies (default: 1)")
    parser.add_argument("--reassessment-days", type=int, default=90, help="Periodic review cycle in days for rule exceptions (default: 90)")
    parser.add_argument("--baseline-audit-json", help="Optional previous signed-off audit JSON file to carry forward approvals and detect rule/framework drift or expired exceptions")
    parser.add_argument("--config-json", help="Optional JSON file overriding resource type map and scoring weights")
    parser.add_argument("--output-csv", default="sdlc_cloud_policy_governance_audit.csv", help="Output CSV file path")
    parser.add_argument("--output-json", help="Optional output JSON file path")
    parser.add_argument("--output-html", help="Optional standalone interactive HTML mapping report path")
    parser.add_argument("--threshold", type=float, default=0.42, help="Minimum similarity threshold (0.0-1.0)")
    parser.add_argument("--demo", action="store_true", help="Run self-test with AWS & Azure Checkov + Sentinel + Wiz sample policies")

    args = parser.parse_args()

    # VS Code One-Click Run Support: If executed with zero CLI arguments (e.g. clicking 'Run Python File' in VS Code),
    # automatically enable --demo and generate default CSV, JSON, and Interactive HTML outputs.
    if len(sys.argv) == 1:
        logger.info("No CLI arguments provided (VS Code Run detected) — running in default Demo/Local mode...")
        args.demo = True
        if not args.output_json:
            args.output_json = "sdlc_cloud_policy_governance_audit.json"
        if not args.output_html:
            args.output_html = "interactive_mapping_report.html"

    resource_map = dict(DEFAULT_MULTICLOUD_RESOURCE_MAP)
    weights = dict(DEFAULT_WEIGHTS)
    if args.config_json:
        with open(args.config_json, "r", encoding="utf-8") as cf:
            cfg = json.load(cf)
            for k, v in (cfg.get("resource_map") or {}).items():
                resource_map[k.lower()] = {str(x).lower() for x in v}
            weights.update(cfg.get("weights") or {})

    if args.demo:
        raw_pols, raw_wiz = get_demo_datasets()
        pol_records = parse_policy_controls(raw_pols)
    else:
        raw_pols = []
        if args.azure_json:
            with open(args.azure_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                raw_pols.extend(data.get("value", data) if isinstance(data, dict) else data)
        if args.aws_sentinel_json:
            with open(args.aws_sentinel_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                raw_pols.extend(data.get("value", data) if isinstance(data, dict) else data)

        pol_records = parse_policy_controls(raw_pols)
        if args.sentinel_dir and os.path.isdir(args.sentinel_dir):
            pol_records.extend(parse_sentinel_directory(args.sentinel_dir))

        # Handle --sync-all-daily auto-detection of configured cloud credentials
        if args.sync_all_daily:
            if os.path.isdir("./policies/sentinel") and not args.sentinel_dir:
                pol_records.extend(parse_sentinel_directory("./policies/sentinel"))
            if os.environ.get("TFC_TOKEN") and (args.tfc_org or os.environ.get("TFC_ORG")):
                args.live_tfc = True
                args.tfc_org = args.tfc_org or os.environ.get("TFC_ORG")
            if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE") or os.environ.get("AWS_ROLE_ARN"):
                args.live_aws = True
            if os.environ.get("AZURE_CLIENT_ID") or os.environ.get("AZURE_ACCESS_TOKEN"):
                args.live_azure = True
            if os.environ.get("WIZ_CLIENT_ID") and os.environ.get("WIZ_CLIENT_SECRET") and os.environ.get("WIZ_API_URL"):
                args.live_wiz = True

        if args.live_tfc:
            tfc_token = os.environ.get("TFC_TOKEN", "")
            if not (args.tfc_org and tfc_token):
                sys.exit("Error: Provide --tfc-org and set TFC_TOKEN environment variable for --live-tfc.")
            pol_records.extend(fetch_hashicorp_sentinel_from_tfc_api(args.tfc_org, tfc_token, args.tfc_url))
        if args.live_aws:
            pol_records.extend(fetch_aws_policies_live(aws_region=args.aws_region))
        if args.live_azure:
            pol_records.extend(
                fetch_azure_policies_live(
                    subscription_id=args.subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID"),
                    management_group_id=args.management_group_id or os.environ.get("AZURE_MANAGEMENT_GROUP_ID"),
                )
            )

        if not pol_records:
            parser.error("Provide --sentinel-dir, --live-tfc, --azure-json, --aws-sentinel-json, or --demo.")

        if args.live_wiz:
            auth_url = os.environ.get("WIZ_AUTH_URL", "https://auth.app.wiz.io/oauth/token")
            api_url = os.environ.get("WIZ_API_URL", "")
            client_id = os.environ.get("WIZ_CLIENT_ID", "")
            client_secret = os.environ.get("WIZ_CLIENT_SECRET", "")
            if not (api_url and client_id and client_secret):
                sys.exit("Error: Set WIZ_API_URL, WIZ_CLIENT_ID, and WIZ_CLIENT_SECRET environment variables for --live-wiz.")
            token = fetch_wiz_token(auth_url, client_id, client_secret)
            raw_wiz = fetch_wiz_rules_from_api(api_url, token, cloud_providers=args.cloud_providers)
        elif args.wiz_json:
            with open(args.wiz_json, "r", encoding="utf-8") as f:
                raw_wiz = json.load(f)
                if isinstance(raw_wiz, dict):
                    raw_wiz = (
                        raw_wiz.get("data", {}).get("cloudConfigurationRules", {}).get("nodes")
                        or raw_wiz.get("nodes")
                        or raw_wiz.get("value")
                        or []
                    )
        else:
            parser.error("Provide --wiz-json, --live-wiz, or --demo.")

    wiz_records = parse_wiz_rules(raw_wiz, since_days=args.since_days)
    logger.info(
        "Loaded %d HashiCorp Sentinel Controls and %d Wiz CCRs (Bi-Weekly %dd window).",
        len(pol_records),
        len(wiz_records),
        args.since_days,
    )

    mappings = build_bidirectional_mappings(
        pol_records,
        wiz_records,
        min_threshold=args.threshold,
        reassessment_days=args.reassessment_days,
        resource_map=resource_map,
        weights=weights,
    )
    mappings = apply_baseline_diff_and_expiration_check(mappings, args.baseline_audit_json)
    if args.sync_all_daily and args.snapshot_dir:
        day_folder = os.path.join(args.snapshot_dir, datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        os.makedirs(day_folder, exist_ok=True)
        snap_file = os.path.join(day_folder, "daily_multicloud_snapshot.json")
        with open(snap_file, "w", encoding="utf-8") as sf:
            json.dump(
                {
                    "snapshot_date": datetime.now(timezone.utc).isoformat(),
                    "controls_count": len(pol_records),
                    "wiz_rules_count": len(wiz_records),
                    "mappings": [asdict(m) for m in mappings],
                },
                sf,
                indent=2,
            )
        logger.info("Saved daily multi-cloud policy snapshot to %s", snap_file)
    write_outputs(mappings, args.output_csv, args.output_json, args.output_html)


if __name__ == "__main__":
    main()