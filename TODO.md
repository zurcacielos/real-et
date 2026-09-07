# KeyVault Comparer - Future Ideas & TODOs

## 1. Export Actionable Security Report (Markdown/PDF)
- Add an "Export Security Report" button in the UI to generate a `.md` file based on the currently filtered grid.
- Include an Executive Summary (e.g., total secrets scanned, total vaults, collisions found).
- Include a Mermaid Diagram mapping how exposed keys connect across multiple environments/services.
- Auto-generate Actionable Scripts (PowerShell/Azure CLI) in the report so engineers can easily verify or mitigate findings.
  - Example: `az keyvault secret show --vault-name X --name Y`
  - Example: `az keyvault secret set --vault-name X --name Y --value "NEW_VALUE"`

## 2. Risk Acceptance (Ignore False Positives)
- Add the ability to right-click a cell and select "Mark as False Positive" or "Accept Risk".
- Save accepted risks to `localStorage` or a config file so they stop triggering vulnerability alerts in future scans.

## 3. Entropy & Dangerous Pattern Detection
- Add a static analysis engine on the frontend to detect secrets that aren't necessarily duplicated, but are inherently weak or dangerous:
  - Low Entropy: Values like `12345`, `password`, or short strings.
  - Dangerous Patterns: Hardcoded JSON, RSA Private Keys (e.g., `-----BEGIN RSA PRIVATE KEY-----`), JWT tokens in non-production environments.

## 4. Direct Administration Actions (Write Operations)
- Add endpoints to the C# API (e.g., `POST /api/vaults/keys`) to manage secrets directly from the grid.
- **Rotate Secret:** Button to generate a new secure random string and push it to all selected environments simultaneously.
- **Sync Environments:** Button to copy a missing secret value from one environment (e.g., DEV) directly to another (e.g., UAT).

## 5. UI/UX Tweaks
- **Highlight On Click Sync:** Sync the "click-to-highlight" behavior with the Identicon Checkboxes (if "By Row" is selected, highlight only matches in the same row, etc.).
