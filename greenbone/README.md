# Greenbone Stack (Independent Project)

This directory is a standalone Docker Compose deployment for Greenbone Community Edition.
It is intentionally separated from the root `docker-compose.yml` used by Watchdog app services.

## Start

```bash
cd greenbone
docker compose pull
docker compose up -d
```

## Stop

```bash
docker compose down
```

## Access GSAD

Open:

- `https://<host-ip>:9392`

A self-signed certificate is expected by default.

## First-Time Setup Notes

- Initial startup can take a long time while feed data is unpacked and indexed.
- Wait for `gvmd`, `ospd-openvas`, and `gsad` to become healthy before logging in.

Check status:

```bash
docker compose ps
docker compose logs -f gvmd ospd-openvas gsad
```

## Create/Reset Admin User

Create user:

```bash
docker compose exec -u gvmd gvmd gvmd --create-user=admin
```

Set password:

```bash
docker compose exec -u gvmd gvmd gvmd --user=admin --new-password='ChangeMeNow!'
```

List users:

```bash
docker compose exec -u gvmd gvmd gvmd --get-users
```

## Update Feeds/Images

```bash
docker compose pull
docker compose up -d
```

Feeds are persisted in named volumes declared in `docker-compose.yml`.
