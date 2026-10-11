# infra: GnomeHome's Azure side (Phase 6)

Bicep templates for everything the plan puts in Azure. **Nothing here has been deployed.** The templates
compile and pass `bicep lint` (Bicep CLI 0.37), but they've never run against a real subscription, so expect
small fixes on the first deploy. Run `what-if` first (below), which shows every change before making it.

## What gets created

| Module | Resources | Plan link |
| --- | --- | --- |
| `monitoring.bicep` | Log Analytics workspace with a **0.1 GB daily cap**; an action group that pushes to the Azure mobile app and emails you | R-08, FR-16 |
| `notifications.bicep` | A custom table, a data collection endpoint and rule that accept only the four notification kinds, and one log alert rule that pushes to your phone | FR-16 |
| `budget.bicep` | A **$25 monthly budget** that alerts at 50%, 80%, and 100% of actual spend, and at 100% forecast | NFR-11 |
| `keyvault.bicep` | Key Vault **Standard** (no Managed HSM) with purge protection, a rotating storage key, and an optional Databricks key | NFR-03, R-08 |
| `storage.bicep` | ADLS Gen2 account (`raw` for the Pi's uploads, `lake` for Delta tables), encrypted with your key, accepting traffic only from your home IP and trusted Azure services; raw files go cool after 30 days and are deleted after 400 | NFR-03 |
| `databricks.bicep` | Databricks **Premium** workspace (needed for Unity Catalog and serverless SQL) and the access connector Unity Catalog uses to reach storage. No clusters: jobs run serverless | FR-12, R-05, R-08 |
| `checkin.bicep` | Azure OpenAI (keys disabled, Entra ID only), a Container Apps environment, and the weekly check-in job, whose identity reads the summaries and may write only to the `reports` container | FR-18, R-04 |

**Expected cost:** roughly $0 to $50 a month, mostly Databricks serverless (see the plan's cost table). Log
Analytics can't exceed its daily cap, and nothing runs all the time except storage.

## Before you deploy

1. Install the Azure CLI on the Mac: `brew install azure-cli` (Homebrew, your user only). Then `az login`.
2. Find your home public IP: `curl -s https://api.ipify.org`. If your ISP changes it, the Pi's uploads will
   be refused until you update `homePublicIp` and redeploy.
3. Copy the parameters file and fill it in. It's ignored by git:

   ```
   cp infra/main.parameters.example.json infra/main.parameters.json
   ```

   - `homePublicIp`: from step 2
   - `alertEmail`: the account you use in the Azure mobile app
   - `ownerObjectId` (optional): `az ad signed-in-user show --query id -o tsv`
   - `databricksAppObjectId` (optional, enables Databricks with your own key):
     `az ad sp show --id 2ff814a6-3304-4ab8-85cb-cd0e6f879c1d --query id -o tsv`
   - `checkinImage`: leave empty until the check-in image is built (Phase 8)

## Deploy

```
az group create --name rg-gnomehome --location eastus2
az deployment group what-if --resource-group rg-gnomehome --template-file infra/main.bicep --parameters @infra/main.parameters.json
az deployment group create  --resource-group rg-gnomehome --template-file infra/main.bicep --parameters @infra/main.parameters.json
```

`what-if` only shows what would change. `create` makes the changes. The outputs include the storage account
name and the Databricks URL.

## After deploying: the Pi's upload token

The Pi uploads with a **service SAS** on the `raw` container, tied to a stored access policy. It can create
and write files, but it can't read, list, or delete anything. Deleting the policy revokes the token at once.
Bicep can't create stored access policies, so run these once (replace `<account>` with the output):

```
az storage container policy create --account-name <account> --container-name raw \
  --name gnomehome-upload --permissions cw --expiry 2027-10-01 --auth-mode key
az storage container generate-sas --account-name <account> --name raw \
  --policy-name gnomehome-upload --auth-mode key --output tsv > storage_sas
```

Then on the Pi:

```
sudo install -o root -g gnomehome -m 0640 storage_sas /etc/gnomehome/storage_sas
rm storage_sas
sudo nano /etc/gnomehome/gnomehome.toml     # [cloud] storage_account = "<account>"
sudo -u gnomehome env GNOMEHOME_CONFIG=/etc/gnomehome/gnomehome.toml /opt/gnomehome/.venv/bin/gnomehome upload
```

The last command is a dry run that lists what would be uploaded. The nightly timer runs it with `--send`.
To revoke the token: `az storage container policy delete --account-name <account> --container-name raw --name gnomehome-upload`.

## After deploying: push notifications to your iPhone

The deployment creates a data collection endpoint and rule, and one alert rule that pushes to the Azure
mobile app whenever the Pi queues a notification. The Pi needs an identity that can write to that one rule
and nothing else:

```
az ad sp create-for-rbac --name gnomehome-pi-notify --role "Monitoring Metrics Publisher" \
  --scopes <monitorDcrResourceId from the outputs>
```

It prints `appId`, `password`, and `tenant`. On the Pi, put the password in a file and the rest in the config:

```
sudo install -o root -g gnomehome -m 0640 /dev/stdin /etc/gnomehome/monitor_secret <<< '<password>'
sudo nano /etc/gnomehome/gnomehome.toml
#   [cloud] tenant_id = "<tenant>", monitor_client_id = "<appId>",
#           monitor_endpoint = "<monitorEndpoint>", monitor_dcr_id = "<monitorDcrId>"
```

Install the Azure mobile app on the iPhone and sign in with `alertEmail`'s account. The push says only that
GnomeHome needs attention and which kind (an approval, an action taken, a failure, the weekly assessment).
The secret expires after a year by default; `az ad sp credential reset --id <appId>` makes a new one.

## After deploying: the weekly AI check-in

The job needs a container image. Build it on the Mac from the repository root, push it to a registry,
and redeploy with `checkinImage` set:

```
docker build -f deploy/checkin/Dockerfile -t ghcr.io/<you>/gnomehome-checkin:1 .
docker push ghcr.io/<you>/gnomehome-checkin:1     # or an Azure Container Registry (about $5 a month)
```

The image holds code only (no secrets, no data), so a public registry is fine. The job signs in with
its managed identity, reads the summary, writes to the `reports` container, and pushes "check-in ready".

The Pi fetches each report with a read-only token on the `reports` container:

```
az storage container policy create --account-name <account> --container-name reports \
  --name gnomehome-read --permissions r --expiry 2027-10-01 --auth-mode key
az storage container generate-sas --account-name <account> --name reports \
  --policy-name gnomehome-read --auth-mode key --output tsv > reports_sas
```

Install it on the Pi as `/etc/gnomehome/reports_sas` (`root:gnomehome`, `0640`) and enable
`gnomehome-checkin.timer`. Suggestions arrive as incidents that wait for your approval.

## After deploying: Databricks

Unity Catalog setup happens in the Databricks account console, not in Bicep:

1. Assign the workspace to your region's Unity Catalog metastore (the account console creates one for you if
   there isn't one yet).
2. In the workspace, create a **storage credential** from the access connector (its ID is a deployment output),
   then an **external location** for `abfss://lake@<account>.dfs.core.windows.net/` and another for `raw`.
3. Create the catalog: `CREATE CATALOG gnomehome MANAGED LOCATION 'abfss://lake@<account>.dfs.core.windows.net/catalog'`.
4. Create a **serverless SQL warehouse** (smallest size, auto-stop after 5 minutes) for Power BI.
5. Deploy the jobs from [`databricks/`](../databricks/README.md).

## Tear down

```
az group delete --name rg-gnomehome
```

Key Vault keeps deleted keys for 90 days (purge protection), so a redeploy within that time needs a new
`namePrefix` or a manual recovery.

## Decisions and limits

- **Pi to Azure transport.** The plan calls for a WireGuard tunnel. Azure has no managed WireGuard endpoint,
  and a VPN gateway or a VM to terminate one would cost more than the whole budget. For now, uploads use
  HTTPS (TLS 1.2+) with a write-only token, to a storage account that only accepts your home IP. This is
  recorded as an open decision in [`docs/decisions.md`](../docs/decisions.md).
- **Shared key access stays on** because service SAS tokens need it. Everything else (Databricks, the check-in
  job) uses Entra ID.
- **The protected-asset list never leaves the Pi.** Uploading it would store data about the work laptop.
  Protected rows are dropped on the Pi before export, and the cloud trusts the manifest's `guard_checked` flag.
