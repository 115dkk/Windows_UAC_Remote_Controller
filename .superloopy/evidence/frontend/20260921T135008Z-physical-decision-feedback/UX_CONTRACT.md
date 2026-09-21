# Physical decision feedback: implementation-ready contract, not UI proof

Status: design only. User order is physical connectivity, actual authentication
measurement, then feedback implementation if the measured path works. No new
feedback component or delay threshold ships from this document alone.

## Baseline and target

Primary user: the paired Android phone owner deciding a Windows UAC request.
The supplied screenshot and user report establish missing immediate reassurance
for this user's journey; they do not establish prevalence across all users.
Current RequestPanel shows native active phases but becomes an empty request
list after withdrawal. useController blocks duplicate input with a generic busy
state. Diagnostic file-save and release-note changes already shipped alpha.1.

Target is the installed Android Tauri2 shell with React19 DOM in the Android
System WebView provider, Korean primary copy with the existing localization
catalog. The physical phone is SM-S948N; its provider/version and actual window
bounds must be recorded when the visible journey is measured. Native Android
owns authentication, service lifecycle, notifications and secure-window policy.
PC Rust service owns final application. Client owns only presentation.
The Windows management UI is adjacent, not a new decision-capability target.
SEO, editable input, custom gestures, QR redesign and a new design system are
not applicable to this delta.

Design source: repository DESIGN.md and existing ui/src CSS tokens, icons,
request-card and notice-box primitives. No new palette/font/framework. Keep
normal page navigation and system authentication; no app loading takeover.

## Decisions and evidence

1. Show local choice immediately, before bridge completion. Its meaning is only
   input acceptance by the client. Native queued/authenticated/sent/applied are
   distinct later facts. This follows the user's requested self-confirmation.
2. Use a body-free result card, not only an auto-disappearing toast. Keep program,
   path and command content under existing native display expiry; never retain
   those fields in a receipt. Preserve a visible final result until confirmation
   within the running client; broader restart/history durability is separately
   owned by existing native history and must not be promised by the card.
3. Bind native results by full native outcome identity, never last history row,
   nearest timestamp, program label or array position. The read-only ABI14
   decisions DTO and bounded outcome receipts implement that prerequisite.
4. Separate latest local choice from PC outcome. PcEvent::Resolved does not
   identify the winning phone. An earlier already-sent approval may win before
   later denial reaches Rust reservation. Opposite outcome must remain visible.
5. No fabricated progress percentages, mandatory minimum wait, completion from
   animation callbacks, automatic re-approval or retransmission buttons.
   Slow-wait escalation timing stays undecided until a valid physical sample.

Alternatives considered: toast-only loses the result when attention returns;
full-screen progress obscures navigation and adds an unnecessary interruption;
retaining request bodies violates the existing display lifetime; reporting every
request as pending indefinitely hides unknown outcomes. The selected card makes
the decision/result distinction explicit but needs visible-state/native QA.

## State contract and draft copy

| Trigger / owner | Local-choice label | Outcome / next action |
| --- | --- | --- |
| Client input, before bridge reply | 승인을 선택했습니다 / 거절을 선택했습니다 | 실제 접수 전에는 완료·전송으로 표시하지 않는다. |
| Actual native authenticating | 내 선택: 승인 | 본인 확인을 진행하십시오. |
| Native preparation | 내 선택: 승인 또는 거절 | PC에 보낼 응답을 준비 중입니다. |
| Native sending | 내 선택: 승인 또는 거절 | PC로 전송 중입니다. |
| Socket written, no PC result | 내 선택: 승인 또는 거절 | PC의 처리 결과를 기다리고 있습니다. |
| Same-request approved / denied | Preserve actual local choice | PC에서 승인했습니다 / PC에서 거절했습니다. 확인 버튼은 카드만 닫는다. |
| Actual OS authentication cancelled | 내 선택: 승인 | 본인 확인을 취소했습니다. 새 선택은 현재 네이티브 허용 상태에 따른다. |
| Local unknown / refresh failed | Preserve actual local choice | 결과를 확인하지 못했습니다. PC의 요청 상태를 확인하십시오. |
| PC failed / expired / cancelled | Preserve actual local choice | PC에서 처리하지 못했습니다 / 요청 시간이 지났습니다 / PC에서 요청을 취소했습니다. |
| New request or concurrent other result | Keep identities separate | 다른 요청의 결과를 현재 선택의 성공으로 붙이지 않는다. |

Native same-request pc_completed remains a generic PC result, not inferred
approval. Final copy must map this case without manufacturing a decision.
Local time passing is not proof of PC expiry; stalled display becomes unknown
unless a corresponding native terminal result exists. Delayed matching final
receipt can replace local unknown. No action is replayed while refreshing state.

RC-1..RC-4: copy names observed selection, stage, result or next action, without
empty safety promises. Recovery claims require implemented commands. Semantic
Korean review keeps formal project register, modifiers attached to observations
or values, and cancellation separate from failure. Draft copy is not a passed
localized implementation; all introduced strings must enter existing catalogs.

## Lifetime, placement and accessibility

- Body-free feedback belongs in the request region, before the empty state or
  adjacent active request, never on top of navigation or the OS auth dialog.
- Native observations are bounded32 and300seconds; client retention must name
  and test its own bound. Do not promise unlimited or cross-restart receipts.
- A new local selection must not inherit the prior card's dismissal or result.
- Confirmation is presentation-only; it cannot deny/cancel a Windows request.
- Preserve current single page scroll owner and DOM reading order. Wrap long
  localized copy; keep touch targets and visible focus at narrow/enlarged bounds.
- Text plus existing static icon conveys state. Use a polite status announcement
  on semantic change, not on elapsed-time ticks. Never steal focus on completion;
  after explicit card dismissal, restore focus to a sensible requests heading.
- Existing reduced-motion behavior remains. No custom haptic is added without
  physical/provider/settings evidence. Motion impact currently unchanged.
- User coverage includes phone touch, keyboard, TalkBack, large text, long locale,
  locked/background return, duplicate input, multiple paired PCs, lost connection,
  and the counterexample where another phone/earlier action completes the request.

## Traceability and required evidence

| Invariant | Intended owner/files | Acceptance / evidence |
| --- | --- | --- |
| Immediate local choice, no false sent state | useController, RequestPanel or bounded new feedback component | client test with unresolved/rejected bridge; actual rendered input timing |
| Current native action phase | NativeRequestRegistry/Coordinator, NativeActionPhaseOwner | eight pure owner tests plus actual native callback/lifecycle checks |
| Same-request result, opposite outcome preserved | NativeDecisionMeasurements, ABI14 DTO, feedback projection | identity/retry tests; controlled real phone auth + PC application |
| Body expiry unchanged | requestPresentation, RequestPanel | expired/stale snapshot and late receipt tests, body-free rendered card |
| Final card does not instantly vanish | client state owner, existing history handoff | complete/leave/return/dismiss/new-selection tests within declared lifetime |
| Layout/accessibility/localization | existing CSS/tokens/catalogs and gallery | CI actual rendered states, small/enlarged text, focus/status semantics; native phone checks separately |

Actual physical authentication baseline remains unverified. Trial01 had no
verified approval or Windows application and is excluded. CI ping and software
phone results do not satisfy it. The new same-signer measurement APK must produce
actual Android OS-auth/signature observations and a same-request PC receipt,
corroborated by controlled Windows verified/apply/process results. Neither this
contract nor a screenshot will be labelled as that measurement.

Usability method so far: ROOT source-based cognitive walkthrough. No participant
success, comfort or preference result is claimed. CI client screenshots cannot
substitute for native authentication, TalkBack or physical latency evidence.
