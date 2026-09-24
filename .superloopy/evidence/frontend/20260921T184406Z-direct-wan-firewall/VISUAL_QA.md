# Root visual review

Reviewed Windows UI gallery run 35644278818, source 3391008b8972500e4fdc6f77c204c18fa6933e26. Downloaded artifact: gallery-339-windows. UI files are unchanged at 5063620730a1a31e6bc3904f38eb3567cb91e375.

Opened actual PNGs for direct-candidate-ko-760, direct-candidate-ko-text-200, direct-candidate-ar-text-200 and direct-phone-recovery-320. Korean normal/enlarged status and program-specific firewall instructions remain readable and wrap within the card. Arabic enlarged text retains RTL layout; the executable name wraps but remains visible. The narrow phone recovery hint fits above the two-row bottom navigation. Enlarged desktop captures are scrolled viewports, not missing document content.

Verdict: inspected client presentation accepted. Candidate wording explicitly requires a mobile-network connection check and does not present the candidate as confirmed Internet connectivity. Firewall guidance identifies uac-service.exe; it does not ask users to disable their firewall or allow arbitrary executables.

Scope: these are synthetic client screenshots, not native V3 interaction, physical phone authentication, or successful cross-LAN connectivity evidence. Latest-source CI remains separately required.
