# Node lifecycle: archive, forget, Remnawave unregister, full cleanup

Node page > Управление and Agent VPS page > Удаление offer four modes.

Archive: hide node from default list, retain all files, credentials, and VPN.
Forget: delete only the Manager record and revoke the credential. The VPS and
Remnawave Node keep working, but the former orphaned agent cannot authenticate.
Remove from Remnawave: use the existing HTTP API to remove the registered
node and optionally its dedicated, unused profile. Keep local VPS and agent.
Full cleanup: staged agent-only removal of all known installer-owned services,
certs, configs, and finally the agent; finish by removing the Manager record.

This does NOT delete, shut down, or cancel billing for the cloud VPS at its
hosting provider. That requires the separate hoster API and authorization.
Global Docker, OS, system SSH and Certbot packages remain installed to avoid
destroying unrelated workloads.

## Controls

- Permanent actions require typing the exact node code, e.g. RUS10.
- Bridge dependencies and outstanding plans block deletion.
- Before deleting the dedicated Xray profile, Manager revalidates the name
  and that no other Remnawave node references the profile. Unknown
  attachments fail closed.
- Remnawave DELETE responses with 200 JSON or 204 empty body are supported.
- On partial API failure, remote UUIDs are cleared only after success.
  A later retry can finish deleting a dedicated profile.
- Forgetting a local record revokes agent authorization by cascading removal.
- Archive is non-disruptive and reversible.

## Full cleanup (requires Agent v1.1)

1. Verify node identity, typed code, no dependencies, online agent and
   absence of other queued agent tasks.
2. Agent validates its actual local domain, both dedicated Docker Compose
   projects (ONLY nginx and remnanode) and absence of symlinked root paths.
3. Agent stops only these containers without removing global Docker or
   unrelated volumes. It removes exact-domain Certbot certificate/hook,
   installer firewall rule, service, logrotate entry and dedicated managed
   directories /opt/nginx, /opt/remnanode and /var/log/remnanode.
4. Agent reports a structured receipt with matching node/domain before
   any Remnawave API node deletion is attempted.
5. Manager unregisters the saved Node through Remnawave API and optionally
   deletes the dedicated Config Profile if still unshared.
6. Agent schedules a fixed root-owned systemd-run self-uninstall 20 seconds
   after acknowledging the task. This disables/removes the agent service,
   sudoers entry, executable and local agent credential.
7. Manager shows finalize_ack and asks for final confirmation to remove
   the Manager record. Self-uninstallation is shown as SCHEDULED, not
   externally verified; an agent cannot confirm its own disappearance.

If any stage fails, the Manager retains the node and stage information for
inspection. No background work is silently retried.

## Upgrading legacy Agent 1.0.0

The original 1.0.0 agent does not implement cleanup or in-band binary update.
Use the explicit Обновить агент 1.1 button for one SSH compatibility upgrade.
That operation verifies the remembered SSH host-key fingerprint and replaces
only the agent. Routine management and deletion afterward use the agent.
New VPS installs get Agent 1.1.0 automatically.

Simply updating Manager never changes an existing VPS or deletes a node.

API reference: https://docs.rw/api/ (node and config profile DELETE endpoints).


## VPS was deleted manually, but its card remains in Manager

A missing agent heartbeat is not proof of deletion. When a VPS no longer
exists, do NOT select "Полностью очистить VPS": that operation requires a
running Agent v1.1 to do the work and cannot succeed against a dead server.

Open Ноды > Управление. For an offline agent, the first option is now
"Уже удалена — убрать запись из менеджера". Type the exact node code.
This removes only the Manager database record and revokes the agent token,
with no SSH and no Remnawave API calls. The operation does not verify or
destroy resources held at the hoster or registered in Remnawave.
If its Remnawave registration is still present, use the separate
Remnawave deletion option before forgetting.

If a FULL deletion began and the agent vanished before it completed,
the panel offers a second, exceptional option to abandon the UNVERIFIED
deletion and remove the local record. This requires explicit acknowledgment,
ten minutes with no agent heartbeat, no still-leased job and no bridge
dependencies. It leaves a permanent audit event and makes NO claims
about remote cleanup, remaining VPN connections or the hoster's VPS.
