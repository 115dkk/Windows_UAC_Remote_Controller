# User acceptance and rollout ordering

2026-09-19, explicit current-conversation user report:

- Phone identity verification and actual Windows UAC approval acceptance have
  ALREADY been completed. This is user-supplied real-device acceptance evidence,
  not an agent-observed CI result. Earlier blanket unverified descriptions are
  superseded for these completed existing-client tests.
- Publish release37 first. ROOT then starts the actual desktop installer.
- The user will approve that installer UAC request using the existing remote
  approver, providing another actual acceptance observation.
- After PC installation outcome is confirmed, ask the user to install the
  Android release themselves. Do not pre-install or replace the phone app.

The new USB AOA/driver combinations remain separately unverified. The forthcoming
release37 installer approval has not happened yet. Preserve normal Windows UAC
and the existing configured authentication; no policy bypass or automatic
synthetic approval is authorized.
