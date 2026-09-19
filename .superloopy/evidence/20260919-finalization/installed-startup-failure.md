# Existing installed service startup failure

Read-only actual host observations on 2026-09-19, before any attempted service
restart or installer launch in this task:

- Installed controller-app ProductVersion:0.1.0-alpha.36.
- Get-Service and Win32_Service both report UacRemoteController Stopped.
- System SCM Event7024 at18:56:15 KST: service-specific error3841982471,
  hexadecimal0xE5000007.
- Kernel-General boot Event12 at18:56:07 KST and OS LastBootUpTime18:56:06;
  prior shutdown Event13 at18:55:49. This was a startup failure after reboot.
- No uac-service/probe Application crash event was returned in the bounded
  matching Event1000/1001 query.
- Stage7 maps exclusively to provision_current_process_observer before actual
  Ready. This path is unchanged between installed alpha36 and current source.
- Current shipping telemetry collapses all observer subphases into stage7; the
  actual failing native API or ACL policy condition is not established.

The user subsequently stated that PC UAC approval is currently unavailable.
The single requested start attempt returned Windows cancellation from
Start-Process; no service process launch or recovery was confirmed. No retry,
alternate elevation path, service-policy bypass or consent dismissal was used.
Current evidence cannot distinguish individual observer API/policy subphases.
Production failure diagnostics are being added without weakening admission.

Do not attribute this to phone auth, current uninstalled lease/USB code, or an
unobserved runtime crash. Do not relax ACL checks, UAC or OS protection on this
evidence. A single explicit approved existing-service start can distinguish a
boot-only failure from repeatable current startup failure; preserve its outcome.
