# VM deployment & full end-to-end testing walkthrough

This is a practical, start-to-finish walkthrough for standing up AI-RECON
on a throwaway VM and exercising the entire real pipeline — recon scans →
findings → detection rules → alerts → correlations → investigations →
the REST API → the dashboard — against real (not mock, not demo) data.
It complements `docs/operations/deployment.md` (the terse production
reference) with the concrete commands for a from-scratch machine, and
folds in the "how do I know it actually works" verification steps.

**Read this first — there is no authentication anywhere in this
platform** (see `docs/security/threat-model.md`, risk SEC-01). That's an
accepted, documented tradeoff for a single-operator CLI tool, not an
oversight — but it means the moment you deploy this to a VM, anyone who
can reach the server's port owns it completely: every asset, finding,
and the ability to trigger scans from your VM's IP. The entire guide
below assumes the VM's app ports are **never exposed to the public
internet** — only reached over SSH tunnels / a VPN / a security group
scoped to your own IP. Do not put a reverse proxy with a public
hostname in front of `cmd/server` unless you first put a real
authenticating proxy (e.g. an OAuth2 reverse-proxy, Tailscale, or a
corporate VPN) in front of *that*.

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
everything else stays loopback/tunnel-only:

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

# Node.js (for the dashboard) — via nodesource, or any LTS you prefer
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt install -y nodejs
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
which is fine for a single-VM deployment reachable only via SSH tunnel;
if you ever bind it wider, set `requirepass` in `/etc/redis/redis.conf`.

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

Add your dashboard's origin to CORS if you're serving the frontend from
somewhere other than `localhost:5173` (e.g. behind the SSH tunnel below,
it still shows up as `localhost` to the browser, so the default in
`configs/development/config.yaml` usually just works):

```
AI_RECON_SERVER_ALLOWED_ORIGINS=http://localhost:5173
```

## 6. Run migrations

```bash
source .env  # or `export $(grep -v '^#' .env | xargs)`
go run ./cmd/migrate up
go run ./cmd/migrate version   # confirm it's current
```

## 7. Start the backend

For real testing, running it directly in a terminal (or under `screen`/
`tmux`) is simplest:

```bash
go run ./cmd/server
```

For anything longer-lived, a systemd unit is the standard shape — see
`docs/operations/deployment.md`'s Startup section for the binary layout;
a minimal unit:

```ini
# /etc/systemd/system/airecon-server.service
[Unit]
Description=AI-RECON API server
After=postgresql.service redis-server.service

[Service]
EnvironmentFile=/home/youruser/ai-recon-platform/ai-recon-platform/.env
ExecStart=/home/youruser/go/bin/server
Restart=on-failure
User=youruser

[Install]
WantedBy=multi-user.target
```

(Build the binary first — `go build -o ~/go/bin/server ./cmd/server` —
`ExecStart` doesn't run `go run`.)

Confirm it's alive:

```bash
curl -s http://localhost:8080/health
curl -s http://localhost:8080/ready   # checks Postgres + Redis too
```

## 8. Reach it from your laptop

Since the app port is firewalled off, tunnel it over SSH rather than
opening it up:

```bash
ssh -L 8080:localhost:8080 -L 5432:localhost:5432 youruser@your-vm-ip
```

(The Postgres tunnel is optional — only useful if you want to poke at
the database directly from your laptop with `psql`/a GUI client.)

## 9. Create and authorize a target, then run real scans

This is the actual "test the whole thing" part. `example.com` (RFC
2606) is a safe, real, already-authorized-by-convention target to point
every scan type at without needing separate authorization — swap in
your own authorized target once you trust the pipeline.

```bash
go run ./cmd/cli target create --type DOMAIN --value example.com \
  --name "VM Test Target" --description "End-to-end test on the VM"
go run ./cmd/cli target authorize --target example.com \
  --authorized-by "<your name>" --method "RFC 2606 test domain"

go run ./cmd/cli scan --target example.com          # HTTP discovery
go run ./cmd/cli network-scan --target example.com  # TCP connect discovery
go run ./cmd/cli dns-scan --target example.com      # DNS + subdomains
go run ./cmd/cli endpoint-scan --target example.com # endpoint/API surface

go run ./cmd/cli findings --target example.com      # detect findings from what was just collected
go run ./cmd/cli fingerprint --target example.com   # passive technology fingerprinting
```

## 10. Install and run detection rules

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

## 11. Correlate and investigate

```bash
go run ./cmd/cli correlation evaluate --target example.com \
  --from "$FROM" --to "$TO"
go run ./cmd/cli correlation list  # get the correlation id
go run ./cmd/cli correlation investigate <correlation-id> --actor "<your name>"
go run ./cmd/cli investigate list --target example.com
go run ./cmd/cli investigate show <investigation-id>
```

## 12. Build and serve the dashboard

```bash
cd frontend
npm install
cp .env.example .env.local
```

Edit `frontend/.env.local`:

```
VITE_API_BASE_URL=http://localhost:8080/api/v1
```

For quick testing, the dev server is simplest (tunnel port 5173 too, or
run it on the VM and tunnel just that one port from your laptop):

```bash
npm run dev -- --host 127.0.0.1
```

then from your laptop:

```bash
ssh -L 8080:localhost:8080 -L 5173:localhost:5173 youruser@your-vm-ip
```

and open `http://localhost:5173`. For something more permanent, build
the static bundle and serve it with nginx/Caddy on the VM instead:

```bash
npm run build       # outputs frontend/dist
```

Point a local static file server (or nginx `root`) at `frontend/dist`,
still only reachable via the tunnel/VPN — never a public hostname, per
the warning at the top of this guide.

## 13. Verify it's real, end to end

In the dashboard, confirm what you did on the CLI actually shows up:

- **Dashboard**: asset/finding/alert/investigation counts match what
  the CLI reported.
- **Assets / Findings**: the exact hostnames/paths/headers your scans
  observed.
- **Detections / Alerts**: any rule that matched, with its evidence.
- **Investigations**: the one you created via `correlation investigate`,
  including its attached evidence and timeline.
- **Analytics**: `/api/v1/analytics/overview` numbers matching the raw
  counts (spot-check with `curl` if anything looks off).

If a page shows nothing, check the obvious things first: is the right
target selected in the dashboard's target switcher, does
`curl http://localhost:8080/api/v1/targets` list it, and does
`GET /ready` report both dependencies `ok`.

## 14. Tearing down / resetting

```bash
sudo systemctl stop airecon-server   # if you set up the unit
sudo -u postgres psql -c "DROP DATABASE airecon_prod;"
```

To start a clean test run without dropping the whole database, deleting
the target cascades everything hung off it (assets, findings, rules,
alerts, investigations, correlations) — check
`docs/operations/runbook.md` for the exact cascade behavior before
relying on it in anything you care about keeping.
