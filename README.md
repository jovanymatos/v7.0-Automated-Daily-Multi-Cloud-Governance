# Multi-Cloud (AWS & Azure) Wiz ⇄ HashiCorp Sentinel ⇄ Checkov Governance Workbench (v7.0 Daily Process)

Enterprise Policy-as-Code 1:1:1 Tri-Mapping, Bidirectional Gap Analysis, and Automated Daily SDLC Audit Governance for **AWS (`aws_*`)** and **Microsoft Azure (`azurerm_*`)**.

## 1. Purpose & Audit Remediation Context

This repository provides a repeatable, automated **Software Development Lifecycle (SDLC) Governance & Rule Exception Framework** for cloud security policies across AWS and Azure:
- **Daily (24-Hour) Automated Policy Intake**: Captures newly released or modified **AWS Config Rules & SCPs**, **Azure Policy Definitions**, **HCP Terraform Sentinel Policies**, **Checkov Checks**, and **Wiz Cloud Configuration Rules (CCRs)** every 24 hours (`--sync-all-daily --since-days 1`) and routes them through formal architectural evaluation, testing, and approval.
- **Interactive Policy Creation Date Window Filter**: Filter policy creation and update dates dynamically across **Last 1 Day (24h)**, **Last 7 Days**, **Last 30 Days**, **Last 90 Days**, **Last 180 Days**, **Last 365 Days (1 Year)**, or **All Creation Dates**.
- **3-Layer Defense-in-Depth Crosswalk**:
  - **Layer 1 (CI / PR Static Analysis)**: **Checkov** (`CKV_AWS_*`, `CKV_AZURE_*`, and Custom Checkov YAML policies).
  - **Layer 2 (Pre-Apply Deployment Gate)**: **HashiCorp Sentinel** (`tfplan/v2` `.sentinel` policies and `sentinel.hcl` enforcement levels: `hard-mandatory`, `soft-mandatory`, `advisory`).
  - **Layer 3 (Runtime & Security Graph Posture)**: **Wiz Cloud Configuration Rules** (`cloudConfigurationRules`, Security Graph controls, and Custom OPA Rego `.rego` policies).
- **Formal Rule Exception Inventory & 90-Day Periodic Reassessment**: Tracks excluded/disabled rules (`enabled: false`), records documented architectural justification and workstream approvers (`Policies Review` / `Custom Rule Management`), and automatically flags expired exceptions (`--reassessment-days 90`) via stateful baseline diffing (`--baseline-audit-json`).
- **Regulatory Crosswalk Support**: Automatically extracts and correlates **CSA Cloud Controls Matrix (CCM v4)**, **CIS AWS & Azure Benchmarks**, **NIST SP 800-53 Rev 5**, **PCI-DSS v4.0**, **FFIEC**, and **SOX ITGC** control IDs.

## 2. Repository Directory Structure

```text
wiz-sentinel-checkov-governance-repo/
├── README.md                                                     # Repository architecture, setup, and daily operating guide
├── .gitignore                                                    # Blocks secrets, tokens, .env, and Terraform state files
├── requirements.txt                                              # Optional cloud SDKs (core CLI runs on 100% Python stdlib)
├── azure_to_wiz_mapper.py                                        # Production Python 3 Daily Sync & 1:1:1 Mapping CLI (v7.0)
├── azure_wiz_mapping_analyzer.html                               # Interactive Visual Governance Workbench & Code Studio (v7.0)
├── .github/
│   └── workflows/
│       └── daily_multicloud_policy_sync.yml                      # Automated Daily (06:15 UTC) GitHub Actions Sync & Drift PR pipeline
├── config/
│   └── custom_taxonomy.json                                      # Externalized AWS/Azure resource map & scoring weights (--config-json)
├── data/
│   └── baseline_sdlc_audit.json                                  # Signed-off baseline snapshot for stateful drift & expiration diffing
├── docs/
│   └── wiz_sentinel_workbench_one_pager.pdf                      # Printable 1-Page Executive & Analyst Operating Guide (v7.0)
├── policies/
│   ├── checkov/
│   │   └── custom_checks.yaml                                    # Layer 1: Custom Checkov YAML policies for IDE/PR static scanning
│   ├── sentinel/
│   │   ├── sentinel.hcl                                          # Layer 2: HashiCorp Sentinel policy set configuration
│   │   ├── aws/
│   │   │   └── enforce-aws-s3-block-public-access.sentinel       # AWS S3 Public Access Block hard-mandatory Sentinel rule
│   │   └── azure/
│   │       └── enforce-azurerm-storage-https-only.sentinel       # Azure Storage HTTPS-only hard-mandatory Sentinel rule
│   └── wiz_rego/
│       └── custom_ccr_rules.rego                                 # Layer 3: Custom Wiz OPA Rego rules for runtime drift detection
└── reports/
    ├── sdlc_cloud_policy_governance_audit.csv                    # Full 37-column SDLC audit ledger (CSV)
    └── interactive_mapping_report.html                           # Standalone shareable interactive HTML mapping report
```

## 3. All Four Execution & Data Ingestion Options

### Option 1: Browser-Only Offline Mode (Zero Python, Zero Credentials)
1. Double-click `azure_wiz_mapping_analyzer.html` to open it in Chrome, Edge, or Firefox.
2. Open **Tab 2 (`2. Live Browser Mapping Engine`)**, upload your downloaded Sentinel JSON and Wiz CCR JSON files under **Option B** (or load an existing CSV/JSON report under **Option A**), and click **Run 1:1 Engine in Browser**.
3. Use the **Policy Creation Date** dropdown (`1 Day`, `7 Days`, `30 Days`, `90 Days`, `180 Days`, `365 Days`, `All Dates`) or the **1. Daily Intake Queue** filter on **Tab 1**, record SME sign-offs inside the **Inspect** modal, and click **`Export CSV`**, **`Export Audit JSON`**, or **`Export Interactive Report (.html)`**.

### Option 2: Local Python CLI in VS Code (Zero-Argument or Offline Batch Mode)
- **One-Click VS Code Run**: Open `azure_to_wiz_mapper.py` in VS Code and click **Run Python File (▷)** — it automatically runs with `--since-days 1` and writes all CSV, JSON, and HTML reports.
- **Custom Batch CLI**: Run `python3 azure_to_wiz_mapper.py --sentinel-dir ./policies/sentinel --wiz-json ./wiz_rules_export.json --baseline-audit-json ./data/baseline_sdlc_audit.json --config-json ./config/custom_taxonomy.json --since-days 1 --reassessment-days 90 --output-csv ./reports/sdlc_cloud_policy_governance_audit.csv --output-json ./data/baseline_sdlc_audit.json --output-html ./reports/interactive_mapping_report.html`.

### Option 3: Live Multi-Cloud Daily API Pull (AWS + Azure + Wiz + HCP Terraform + Checkov)
Set `TFC_TOKEN`, `WIZ_API_URL`, `WIZ_CLIENT_ID`, and `WIZ_CLIENT_SECRET` (plus AWS/Azure OIDC or CLI credentials) in your environment, then run:
```bash
python3 azure_to_wiz_mapper.py --sync-all-daily --since-days 1 --reassessment-days 90
```

### Option 4: Automated GitHub Actions Daily Workflow
1. Upload this repository to GitHub.
2. In your GitHub repository, navigate to **Settings → Secrets and variables → Actions** and add Repository Secrets (`TFC_TOKEN`, `WIZ_API_URL`, `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`) and Repository Variables (`TFC_ORG`, `AWS_ROLE_ARN`, `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`).
3. The workflow `.github/workflows/daily_multicloud_policy_sync.yml` runs automatically every day at `06:15 UTC` (or on-demand via **Actions → Run workflow** with custom `since_days` and `reassessment_days` inputs) and publishes the updated CSV, JSON, dated snapshot (`data/daily_snapshots/YYYY-MM-DD/`), and interactive HTML report.
