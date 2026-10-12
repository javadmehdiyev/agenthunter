# Deploy guide — Linux ARM64 server + your own domain + automatic HTTPS

Architecture: the Go app listens on `127.0.0.1:8080`. **Caddy** sits in front on
ports 80/443 and gets a free Let's Encrypt certificate for your domain
automatically. You never touch certbot.

Throughout, replace:
- `your-domain.com` → your real domain
- `SERVER_IP` → your server's public IP
- `user` → your SSH username (often `root` or `ubuntu`)

---

## Step 1 — Point your domain at the server (DNS)

In your domain registrar's DNS panel, create:

| Type | Name | Value        | TTL  |
|------|------|--------------|------|
| A    | `@`  | `SERVER_IP`  | 300  |
| A    | `www`| `SERVER_IP`  | 300  |

Wait for it to propagate (usually minutes). Verify from your laptop:

```bash
dig +short your-domain.com      # should print SERVER_IP
```

> Caddy will NOT be able to issue a certificate until DNS points at the server,
> so do this first.

## Step 2 — Open the firewall

On the server (and in your cloud provider's security group / firewall):

```bash
sudo ufw allow 22,80,443/tcp   # if using ufw
sudo ufw enable
```

Port 8080 stays closed to the public — only Caddy (local) reaches it.

## Step 3 — Build and upload the app

From your Mac (in the project folder):

```bash
./deploy/build.sh user@SERVER_IP
```

This builds `dist/agent-illusion` (linux/arm64) and copies it to
`/opt/agent-illusion/agent-illusion` on the server.

## Step 4 — Install the systemd service

Upload the unit and files, then enable it:

```bash
# from your Mac:
scp deploy/agent-illusion.service user@SERVER_IP:/tmp/

# then on the server (ssh user@SERVER_IP):
sudo mv /tmp/agent-illusion.service /etc/systemd/system/
# IMPORTANT: set a long random dashboard secret:
sudo sed -i "s/CHANGE_ME_to_a_long_random_secret/$(openssl rand -hex 24)/" /etc/systemd/system/agent-illusion.service
sudo systemctl daemon-reload
sudo systemctl enable --now agent-illusion
sudo systemctl status agent-illusion      # should be active (running)
curl -s localhost:8080/ | head -c 80       # sanity check
```

Note the secret you set — you'll need it for the dashboard:
```bash
grep MONITOR_TOKEN /etc/systemd/system/agent-illusion.service
```

## Step 5 — Install Caddy (handles HTTPS automatically)

On the server (Ubuntu/Debian ARM64):

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
```

Then install the Caddyfile:

```bash
# from your Mac:
scp deploy/Caddyfile user@SERVER_IP:/tmp/

# on the server:
sudo mv /tmp/Caddyfile /etc/caddy/Caddyfile
sudo sed -i 's/your-domain.com/YOUR_REAL_DOMAIN/g' /etc/caddy/Caddyfile
sudo mkdir -p /var/log/caddy
sudo systemctl restart caddy
sudo systemctl status caddy
```

Within ~30 seconds Caddy fetches the certificate. Visit:

```
https://your-domain.com            # the honeypot site (valid HTTPS)
https://your-domain.com/_monitor?token=YOUR_SECRET   # the dashboard
```

---

## Updating later

Change code, then just:

```bash
./deploy/build.sh user@SERVER_IP   # rebuilds + uploads + restarts the service
```

## Troubleshooting

- **Cert not issuing** → DNS isn't pointing at the server yet, or port 80/443
  blocked. Check `dig +short your-domain.com` and the firewall. Logs:
  `sudo journalctl -u caddy -n 50`.
- **502 Bad Gateway** → the Go service isn't running. `sudo systemctl status agent-illusion`.
- **App logs / beacon hits** → `sudo journalctl -u agent-illusion -f` and
  `/opt/agent-illusion/events.jsonl`.

## Security notes for a honeypot on a public domain

- Keep `MONITOR_TOKEN` set so `/_monitor` isn't world-readable. Optionally also
  restrict it by IP in the Caddyfile (commented block included).
- The injected prompts only trigger harmless GETs back to your own server — safe
  to expose publicly. Do not add payloads that target third parties.
- Since this is a research honeypot, consider isolating the VM (separate project,
  minimal privileges) so a misbehaving agent that *does* act can't reach anything
  else of yours.
