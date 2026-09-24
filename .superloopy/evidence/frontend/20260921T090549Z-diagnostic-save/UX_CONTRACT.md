# Diagnostic save — bounded existing-system delta

Target: installed Android36 Tauri app, React DOM WebView client and Android SAF.
Owner: client exposes two distinct actions; native Activity owns file picker and
URI access; exporter worker owns bounded diagnostic read/write. Native service,
authentication and request authority unchanged. Windows action unchanged.

User job: retrieve a diagnostic text file without selecting another receiving
application. Current share creates Downloads/UAC Remote Approval then always
opens Sharesheet. Add explicit file-save action first, keep share second.
Save returns saved only after write/close, cancelled is normal, failure gives
location/space recovery. No filename or arbitrary URI/path comes from JavaScript.
Pending save blocks repeated save/share and has aria-busy; history survives.
When external picker hides client, existing request-body withdrawal remains.

Design authority: DESIGN.md existing secondary buttons, collection-actions wrap,
space-3 gap,48px phone target, main scroll owner. No new tokens/animation/imagery.
New strings use all11 catalogs. Scope is diagnostic recovery, not a request UI
redesign. Approval feedback remains a researched proposal in docs/decision-feedback-research.md.

Evidence floor: CI unit/controller outcomes saved/cancelled/failure, repeated tap,
unavailable history, pending reads; CI client gallery320px/dark/200%text and keyboard;
native Kotlin state tests and actual Android provider/instrumentation evidence.
Client synthetic evidence never substitutes for SAF file creation. Final native
claims must match artifacts. User device not connected; hardware test deferred.

Preference warrant: explicit user requirement for storage without Sharesheet.
Alternative (only explaining existing Downloads location) rejected because it
retains compulsory sharing and hides the intended save action. No usability
study claimed; this is a source-based reviewer walkthrough.
