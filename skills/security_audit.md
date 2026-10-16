# Skill: Project Talos - Trap & Trace
Use this to manage deception traps and respond to Mini Shai-Hulud alerts.

## Phase 1: Setup
- Call `deploy_canaries` to prime the environment.

## Phase 2: Monitoring (Triggered by Sentry)
- When a NemoClaw block occurs, first call `audit_canary_access`.
- If a canary was triggered, the threat has already moved to the 'Scavenging' phase.
- Immediately execute `find_evil_scan` on both `c:\Users\z143d\Desktop\Project-Ares-SANS` and `c:\Users\z143d\Desktop\Aergia_Studio`.

## Phase 3: Protocol SIFT Remediation
- **Isolate**: Pause all Docker containers.
- **Purge**: Search for `intercom-client@7.0.4` or `lightning==2.6.2/3` in dependencies.
- **Report**: Generate a SANS-standard incident report for the hackathon.
