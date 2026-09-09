# Docker operations and recovery

## Start and stop

```bash
# Download and start the container
docker compose pull
docker compose up -d

# Check status
docker compose ps

# Restart after changing settings
docker compose restart app

# Stop without deleting data
docker compose down
```

Do not add `-v` to `docker compose down` unless you intend to delete the installation.

## Container output

```bash
docker compose logs -f --tail 100 app
```

Remove credentials, player identifiers, private chat, and internal addresses before sharing output in a report.

## Health checks

- `https://localhost:8787/healthz` checks whether the web service is responding.
- `https://localhost:8787/readyz` checks whether the configured services are ready.

Use the generated CA certificate when monitoring these endpoints. Do not disable certificate verification in production monitoring.

## Backups

Back up these Docker volumes:

- `blcksnake-command_data`
- `blcksnake-command_keystore`
- `blcksnake-command_logs` when retained activity records are required

Stop the container or use a crash-consistent volume snapshot. The data and keystore backups belong together, but should be protected separately.

## Restore

Restore the data and matching keystore volumes under their original names, then run:

```bash
docker compose up -d
docker compose ps
```

If the dashboard asks for a new owner, stop the container. The expected data or keystore volume is missing or attached under the wrong name.

## Update

Create a backup, then run:

```bash
docker compose down
docker compose pull
docker compose up -d
docker compose ps
```

Sign in and check the maps and integrations after the update.

## HTTPS certificate

Display the current public CA:

```bash
docker compose exec app npm run tls:show-ca
```

Export it to the host:

```bash
docker compose exec app npm run tls:export-ca -- --out /tmp/blcksnake-command-ca.pem
docker compose cp app:/tmp/blcksnake-command-ca.pem ./blcksnake-command-ca.pem
```

To replace the HTTPS identity, stop the service and supply every additional DNS name or IP address it needs:

```bash
docker compose stop app
docker compose run --rm app npm run tls:rotate -- --name admin.example.net --name 10.20.30.40
docker compose up -d app
```

Install the new CA on administrator devices before using the replacement identity.

## Credential exposure

If a credential may have been disclosed:

1. Restrict dashboard and RCON network access.
2. Preserve a backup of the data, keystore, and log volumes.
3. Rotate the affected RCON, SFTP, Discord, operator, or automation credential.
4. Restart the container and verify the affected connection.

Report security problems privately. Do not attach credentials, database and key pairs, player identifiers, private chat, or unsanitized output.
