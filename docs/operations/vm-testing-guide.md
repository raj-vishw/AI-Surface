# VM deployment & full end-to-end testing walkthrough

This is a practical, start-to-finish walkthrough for standing up AI-RECON
on a throwaway VM and exercising the entire real pipeline — recon scans →
findings → detection rules → alerts → correlations → investigations —
against real (not mock, not demo) data. It complements
`docs/operations/deployment.md` (the terse production reference) with
the concrete commands for a from-scratch machine, and folds in the "how
do I know it actually works" verification steps.

This platform is CLI-only — there is no server process and no dashboard.
Every action below runs directly against the VM's own Postgres/Redis via
`cmd/cli`. **Read this first — there is no authentication anywhere in
this platform** (see `docs/security/threat-model.md`, risk SEC-01):
anyone with shell access to the VM has full access to everything the CLI
can see or do. Never expose Postgres/Redis to the public internet —
loopback-only, reached over SSH if you ever need to poke at the database
directly from your laptop.

## 1. Provision the VM

Any small Linux VM works — this doesn't need much:

- **Cloud**: a $6-12/mo droplet/VM (DigitalOcean, Hetzner, a free-tier
  AWS/GCP instance) — Ubuntu 22.04/24.04 or Debian 12, 2 vCPU / 2-4GB
  RAM, 20GB disk is comfortable.
- **Local**: VirtualBox/UTM/`multipass launch` with the same OS — fine
  for testing since nothing here needs to be internet-reachable.

Either way, once it's up:

```bash
ssh youruser@your-vm-ip
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git build-essential ufw
```

Lock the firewall down before anything else — SSH only from the outside;
everything else stays loopback-only:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw enable
```

## 2. Install the runtime dependencies

```bash
# Go (match go.mod's toolchain version)
GOVER=$(curl -s https://go.dev/VERSION?m=text | head -1)
curl -LO "https://go.dev/dl/${GOVER}.linux-amd64.tar.gz"
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "${GOVER}.linux-amd64.tar.gz"
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
go version

# PostgreSQL 16+ and Redis
sudo apt install -y postgresql postgresql-contrib redis-server
sudo systemctl enable --now postgresql redis-server
```

## 3. Get the code onto the VM

```bash
git clone <your-fork-or-repo-url> ai-recon-platform
cd ai-recon-platform/ai-recon-platform
go build ./...   # sanity check before touching the database
```

(If you don't want to push to a remote, `scp -r` or `rsync -av` the
working tree over instead — just make sure `.git` history isn't your
only copy of anything uncommitted.)

## 4. Set up PostgreSQL and Redis

```bash
sudo -u postgres psql -c "CREATE ROLE airecon WITH LOGIN PASSWORD 'CHANGE-ME';"
sudo -u postgres psql -c "CREATE DATABASE airecon_prod OWNER airecon;"
```

Redis's default install has no password and only listens on localhost,
which is fine for a single-VM deployment; if you ever bind it wider, set
`requirepass` in `/etc/redis/redis.conf`.

## 5. Configure the app

```bash
cp .env.example .env
```

Edit `.env` (or export these directly) — at minimum:

```
AI_RECON_APP_ENV=production
AI_RECON_DATABASE_HOST=127.0.0.1
AI_RECON_DATABASE_USER=airecon
AI_RECON_DATABASE_PASSWORD=CHANGE-ME
AI_RECON_DATABASE_NAME=airecon_prod
AI_RECON_DATABASE_SSL_MODE=disable
AI_RECON_REDIS_ADDRESS=127.0.0.1:6379
```

`AI_RECON_APP_ENV=production` activates `configs/production/config.yaml`
plus the startup guard rails in `Config.Validate()` — see
`docs/security/production-hardening.md`. If you're just testing (not
trying to model a real production posture), `AI_RECON_APP_ENV=development`
is fine too and slightly more forgiving.

## 6. Run migrations

```bash
source .env  # or `export $(grep -v '^#' .env | xargs)`
go run ./cmd/migrate up
go run ./cmd/migrate version   # confirm it's current
```

## 7. Create and authorize a target, then run real scans

This is the actual "test the whole thing" part. `example.com` (RFC
2606) is a safe, real, already-authorized-by-convention target to point
every scan type at without needing separate authorization — swap in
your own authorized target once you trust the pipeline.

```bash
go run ./cmd/cli target create --type DOMAIN --value example.com \
  --name "VM Test Target" --description "End-to-end test on the VM"
go run ./cmd/cli target list   # grab the id printed above
go run ./cmd/cli target authorize --id <target-id> --status AUTHORIZED

go run ./cmd/cli scan --target example.com          # HTTP discovery
go run ./cmd/cli network-scan --target example.com --profile quick  # TCP connect discovery
go run ./cmd/cli dns-scan --target example.com      # DNS + subdomains
go run ./cmd/cli endpoint-scan --target example.com # endpoint/API surface

go run ./cmd/cli findings scan --target example.com  # detect findings from what was just collected
go run ./cmd/cli fingerprint --target example.com    # passive technology fingerprinting
```

## 8. Install and run detection rules

```bash
go run ./cmd/cli detection builtin list
for rule in high_severity_finding_burst new_finding_after_asset_change \
            repeated_malicious_intelligence_signal technology_change_spike \
            critical_exposure_finding; do
  go run ./cmd/cli detection builtin install "$rule" --target example.com \
    --created-by "<your name>" --enable
done
```

Evaluate each rule against what was actually collected (adjust `--from`
to cover when your scans ran):

```bash
FROM=$(date -u -d '-1 hour' +%Y-%m-%dT%H:%M:%SZ)
TO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
go run ./cmd/cli detection list --target example.com   # get each rule's id
go run ./cmd/cli detection evaluate <rule-id> --from "$FROM" --to "$TO"
```

Zero matches on a benign target like `example.com` is the *correct*
outcome for severity-threshold rules — they only fire on genuinely
high/critical findings. Don't mistake "no alerts yet" for "broken."

## 9. Correlate and investigate

```bash
go run ./cmd/cli correlation evaluate --target example.com \
  --from "$FROM" --to "$TO"
go run ./cmd/cli correlation list  # get the correlation id
go run ./cmd/cli correlation investigate <correlation-id> --actor "<your name>"
go run ./cmd/cli investigate list --target example.com
go run ./cmd/cli investigate show <investigation-id>
```

## 10. Verify it's real, end to end

Everything above already ran against the real database — there's no
separate "did it actually work" layer to check beyond re-reading it back:

```bash
go run ./cmd/cli target list
go run ./cmd/cli findings list --target example.com
go run ./cmd/cli alert list
go run ./cmd/cli investigate list --target example.com
go run ./cmd/cli analytics overview --target example.com
```

If a command reports nothing, check the obvious things first: is the
target actually `AUTHORIZED` (`target list` shows its status), and did
the scan/detection/correlation step that should have produced this data
actually run without error.

## 11. Tearing down / resetting

```bash
sudo -u postgres psql -c "DROP DATABASE airecon_prod;"
```

To start a clean test run without dropping the whole database:
`DELETE FROM targets` fails with a foreign-key violation — the FK from
`assets`/`findings`/etc. back to `targets` is `RESTRICT`, not `CASCADE`.
Use `TRUNCATE targets CASCADE;` instead (as the `airecon` role, via
`psql`) — it cascades to every referencing table regardless of the FK's
own delete rule.
