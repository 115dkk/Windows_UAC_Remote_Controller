// SPDX-License-Identifier: GPL-2.0-or-later
// QA-ONLY drawing of the native Windows pairing ceremony, for the synthetic
// gallery. The real screens are painted by GDI in
// crates/windows-service-host/src/ffi/pairing_client/renderer_ui.rs on a private
// desktop. This is a client mock at the same geometry and copy so the layout can
// be reviewed; it is never native proof, and it holds no invitation.
import { useId, useLayoutEffect, useRef, useState } from 'react';
import { currentLocale, tr } from './i18n';
import { sampleQrModules, sampleQrWidth } from './pairing-ceremony-sample';

export type CeremonyScreen = 'introduction' | 'invitation' | 'comparison';
/** What the phone's secure hardware reported about its start (ADR 0049). The
 * comparison screen adds a sentence for anything but the manufacturer's system. */
export type CeremonyBoot = 'manufacturer' | 'owner' | 'unverified';

// renderer_ui.rs paints in points at the window's DPI. At 96 DPI one point is
// 4/3 of a pixel, which is the only conversion the mock needs.
const pt = (points: number) => `${String((points * 4) / 3)}px`;
const INK = '#152c35';
const MUTED_INK = '#536971';
const FAINT_INK = '#7b8f97';
const ACCENT = '#0b7285';
const CAUTION_SURFACE = '#fff4e0';
const CAUTION_INK = '#7a4f00';
const SURFACE = '#ffffff';
const BORDER = '#d7e3e7';
const BACKGROUND = '#f2f6f7';
const QUIET_MODULES = 4;
const MIN_MODULE_PX = 3;

/** Mirrors `card_rect`: the card the QR screen paints inside. */
function cardRect(width: number, height: number) {
  const cardWidth = Math.min(Math.trunc((width * 72) / 100), 760);
  const cardHeight = Math.min(Math.trunc((height * 96) / 100), 900);
  return { width: cardWidth, height: cardHeight, top: Math.trunc((height - cardHeight) / 2) };
}

/** Mirrors `invitation_layout`: the code is measured first and the footer is
 * anchored to the card, so a cramped display loses margin, not legibility. */
function invitationLayout(cardHeight: number, shorter: number, modules: number) {
  const quiet = modules + QUIET_MODULES * 2;
  const footer = 164;
  const header = Math.max(200, Math.min(214, cardHeight - footer - MIN_MODULE_PX * quiet - 8));
  const band = Math.max(1, cardHeight - header - footer);
  const target = Math.min(Math.trunc((shorter * 38) / 100), band);
  const modulePx = Math.max(MIN_MODULE_PX, Math.trunc(target / quiet));
  const side = modulePx * quiet;
  return {
    modulePx, side,
    qrTop: header + Math.trunc(Math.max(0, band - side) / 2),
    countdownTop: header + Math.trunc(Math.max(0, band - side) / 2) + side + 14,
    buttonTop: cardHeight - 118,
    buttonHeight: 56,
  };
}

/** Mirrors `comparison_layout`, in card coordinates. With no notice the decision
 * row rests where it always has. A notice sits under the digits and the row
 * moves down only as far as the notice needs, never off the card; on a display
 * too cramped for both, the notice gives way, not the row. */
function comparisonLayout(card: { height: number; top: number }, height: number, noticeText: number | null) {
  const buttonHeight = 72;
  const resting = Math.trunc(height / 2) + 120 - card.top;
  if (noticeText === null) return { notice: null, whole: true, padding: 0, buttonTop: resting };
  const top = 286 + 12;
  const gap = 12;
  const lowest = Math.max(card.height - 16 - buttonHeight, resting);
  const padding = noticeText + 16 * 2 <= lowest - gap - top ? 16 : 6;
  const tall = noticeText + padding * 2;
  const buttonTop = Math.min(Math.max(resting, top + tall + gap), lowest);
  const bottom = Math.max(Math.min(top + tall, buttonTop - gap), top);
  return { notice: { top, height: bottom - top }, whole: bottom === top + tall, padding, buttonTop };
}

function SampleCode({ side, modulePx }: { side: number; modulePx: number }) {
  const segments: string[] = [];
  for (let row = 0; row < sampleQrWidth; row += 1) {
    for (let column = 0; column < sampleQrWidth; column += 1) {
      if (!sampleQrModules[row * sampleQrWidth + column]) continue;
      const x = (column + QUIET_MODULES) * modulePx;
      const y = (row + QUIET_MODULES) * modulePx;
      segments.push(`M${String(x)} ${String(y)}h${String(modulePx)}v${String(modulePx)}h-${String(modulePx)}z`);
    }
  }
  return <svg width={side} height={side} viewBox={`0 0 ${String(side)} ${String(side)}`}
    shapeRendering="crispEdges" role="img" aria-label={tr('QR 코드 보기')}
    style={{ display: 'block', background: SURFACE }}>
    <path d={segments.join('')} fill={INK} />
  </svg>;
}

function Signature({ size, room }: { size: number; room: number }) {
  // The native painter drops the name outright when the card would cover it.
  // Measure and hide rather than clip, so the gallery shows what ships.
  const label = useRef<HTMLSpanElement>(null);
  const [fits, setFits] = useState(false);
  useLayoutEffect(() => {
    const node = label.current;
    setFits(node !== null && room > 0 && node.scrollWidth <= room);
  }, [room]);
  const unit = (value: number) => (value * size) / 40;
  const plate = (a: number, b: number, c: number, d: number, fill: string) => ({
    position: 'absolute' as const, left: unit(a), top: unit(b),
    width: unit(c) - unit(a), height: unit(d) - unit(b), background: fill,
  });
  return <div style={{ display: 'flex', alignItems: 'center', gap: size / 4 }}>
    <div style={{ position: 'relative', width: size, height: size, background: ACCENT, borderRadius: size * 0.3 }}>
      <div style={plate(7, 9, 30, 26, SURFACE)} />
      <div style={plate(10, 12, 27, 23, ACCENT)} />
      <div style={plate(12, 29, 25, 31, SURFACE)} />
      <div style={plate(23, 17, 35, 34, SURFACE)} />
      <div style={plate(25, 19, 33, 30, ACCENT)} />
    </div>
    <span ref={label} style={{
      font: `${pt(16)} var(--font-ui)`, color: ACCENT, maxWidth: Math.max(0, room),
      whiteSpace: 'nowrap', visibility: fits ? 'visible' : 'hidden',
    }} data-signature-name>{tr('UAC 원격 승인')}</span>
  </div>;
}

function Button({ label, primary }: { label: string; primary?: boolean }) {
  const paired = primary !== undefined;
  return <button type="button" disabled style={{
    width: paired ? 240 : 300, height: paired ? 72 : 56,
    font: `${pt(16)} var(--font-ui)`, lineHeight: 1.3, color: INK, background: '#fdfdfd',
    border: `1px solid ${primary ? ACCENT : '#adadad'}`, boxShadow: primary ? `0 0 0 1px ${ACCENT}` : 'none',
    borderRadius: 3, padding: '0 8px', overflowWrap: 'break-word', whiteSpace: 'normal',
  }}>{label}</button>;
}

/** The introduction sizes to its own text, exactly as `introduction_layout`
 * does with DT_CALCRECT, so flow layout here is the faithful mirror. */
function Introduction({ width }: { width: number }) {
  const heading = useId();
  const cardWidth = Math.min(Math.trunc((width * 72) / 100), 760);
  return <section aria-labelledby={heading} style={{
    width: cardWidth, background: SURFACE, border: `1px solid ${BORDER}`,
    padding: `${String(26)}px ${String(44)}px ${String(44)}px`, textAlign: 'center',
  }}>
    <h2 id={heading} style={{ margin: 0, height: 66, font: `700 ${pt(22)} var(--font-ui)`, color: INK }}>
      {tr('QR 연결 절차를 시작합니다.')}
    </h2>
    <p style={{ margin: `18px 0 0`, font: `${pt(16)} var(--font-ui)`, color: MUTED_INK }}>
      {tr('휴대폰을 이 PC에 등록합니다. [QR 코드 보기]를 누른 뒤 휴대폰의 UAC 원격 승인기에서 [PC의 QR 코드 촬영]을 누르십시오.')}
    </p>
    <p style={{ margin: `20px 0 0`, font: `${pt(16)} var(--font-ui)`, color: MUTED_INK }}>
      {tr('ESC를 누르거나 [취소]를 눌러 언제든 중지할 수 있습니다.')}
    </p>
    <p style={{
      margin: `26px 0 0`, padding: '20px 24px', background: CAUTION_SURFACE,
      font: `${pt(16)} var(--font-ui)`, color: CAUTION_INK,
    }}>{tr('주의: 다른 사람의 요청으로 이 절차에 들어왔다면 지금 바로 중지하세요. QR 코드를 다른 사람에게 절대 공유하지 마세요.')}</p>
    <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginTop: 32, alignItems: 'stretch' }}>
      <Button label={tr('QR 코드 보기')} primary />
      <Button label={tr('취소')} primary={false} />
    </div>
  </section>;
}

function Comparison({ width, height, boot }: { width: number; height: number; boot: CeremonyBoot }) {
  const heading = useId();
  const card = cardRect(width, height);
  const notice = boot === 'unverified'
    ? tr('이 휴대폰은 부트로더가 풀려 있습니다. 직접 푼 것이 아니라면 ESC를 눌러 중지하십시오.')
    : boot === 'owner'
      ? tr('이 휴대폰은 제조사 것이 아닌 운영체제로 시작했습니다. 직접 설치한 것이 아니라면 ESC를 눌러 중지하십시오.')
      : null;
  // The renderer measures the sentence with DT_CALCRECT in the body font, and in
  // the hint font when the display has no room for that. Two hidden copies at
  // the band's text width stand in for those two measurements.
  const body = useRef<HTMLParagraphElement>(null);
  const hint = useRef<HTMLParagraphElement>(null);
  const [measured, setMeasured] = useState<{ body: number; hint: number } | null>(null);
  const textWidth = Math.max(1, card.width - 44 * 2 - 24 * 2);
  useLayoutEffect(() => {
    const [inBody, inHint] = [body.current, hint.current];
    if (inBody === null || inHint === null) return undefined;
    const measure = () => { setMeasured({ body: inBody.offsetHeight, hint: inHint.offsetHeight }); };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(inBody);
    observer.observe(inHint);
    return () => { observer.disconnect(); };
  }, [notice, textWidth]);
  const inBody = notice === null || measured === null ? null : comparisonLayout(card, height, measured.body);
  const fitted = inBody === null || measured === null ? null
    : inBody.whole ? { layout: inBody, points: 16 }
      : { layout: comparisonLayout(card, height, measured.hint), points: 13 };
  const layout = fitted?.layout ?? comparisonLayout(card, height, null);
  const measuring = (points: number) => ({
    position: 'absolute' as const, visibility: 'hidden' as const, insetInlineStart: 0, top: 0,
    width: textWidth, margin: 0, font: `${pt(points)} var(--font-ui)`,
  });
  return <section aria-labelledby={heading} style={{
    position: 'relative', width: card.width, height: card.height,
    background: SURFACE, border: `1px solid ${BORDER}`, textAlign: 'center',
  }}>
    <h2 id={heading} style={{ position: 'absolute', insetInline: 32, top: 26, height: 70, margin: 0, font: `700 ${pt(22)} var(--font-ui)`, color: INK }}>
      {tr('UAC 원격 승인 · PC 연결')}
    </h2>
    <p style={{ position: 'absolute', insetInline: 36, top: 104, margin: 0, font: `${pt(16)} var(--font-ui)`, color: MUTED_INK }}>
      {tr('휴대폰에 표시된 숫자와 같은지 확인해 주세요.')}
    </p>
    <p style={{ position: 'absolute', insetInline: 36, top: 196, height: 90, margin: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', font: `700 ${pt(40)} 'UAC Sans', var(--font-ui)`, color: INK }}>123 456</p>
    {notice === null ? null : <>
      <p ref={body} aria-hidden style={measuring(16)}>{notice}</p>
      <p ref={hint} aria-hidden style={measuring(13)}>{notice}</p>
    </>}
    {fitted === null || layout.notice === null ? null : <p data-boot-notice style={{
      position: 'absolute', insetInline: 44, top: layout.notice.top, height: layout.notice.height,
      boxSizing: 'border-box', margin: 0, padding: `${String(layout.padding)}px 24px`, overflow: 'hidden',
      background: CAUTION_SURFACE, font: `${pt(fitted.points)} var(--font-ui)`, color: CAUTION_INK,
    }}>{notice}</p>}
    <div data-comparison-actions style={{
      position: 'absolute', insetInline: 0, top: layout.buttonTop,
      display: 'flex', gap: 16, justifyContent: 'center',
    }}>
      <Button label={tr('숫자가 같아요')} primary />
      <Button label={tr('다릅니다, 취소')} primary={false} />
    </div>
  </section>;
}

function Invitation({ width, height }: { width: number; height: number }) {
  const heading = useId();
  const card = cardRect(width, height);
  const layout = invitationLayout(card.height, Math.min(width, height), sampleQrWidth);
  return <section aria-labelledby={heading} style={{
    position: 'relative', width: card.width, height: card.height,
    background: SURFACE, border: `1px solid ${BORDER}`, textAlign: 'center',
  }}>
    <h2 id={heading} style={{ position: 'absolute', insetInline: 32, top: 26, height: 70, margin: 0, font: `700 ${pt(22)} var(--font-ui)`, color: INK }}>
      {tr('UAC 원격 승인 · PC 연결')}
    </h2>
    <p style={{ position: 'absolute', insetInline: 36, top: 104, margin: 0, font: `${pt(16)} var(--font-ui)`, color: MUTED_INK }}>
      {tr('UAC 원격 승인 앱에서 [PC의 QR 코드 촬영]을 누르고 이 QR을 비춰 주세요.')}
    </p>
    <div style={{ position: 'absolute', left: Math.trunc((card.width - layout.side) / 2), top: layout.qrTop }}>
      <SampleCode side={layout.side} modulePx={layout.modulePx} />
    </div>
    <p style={{ position: 'absolute', insetInline: 24, top: layout.countdownTop, margin: 0, font: `${pt(16)} var(--font-ui)`, color: MUTED_INK }}>
      {tr('{:02}:{:02} 후 종료').replace('{:02}:{:02}', '01:47')}
    </p>
    <div style={{ position: 'absolute', insetInline: 0, top: layout.buttonTop, display: 'flex', justifyContent: 'center' }}>
      <Button label={tr('취소하고 돌아가기')} />
    </div>
    <p style={{ position: 'absolute', insetInline: 24, bottom: 16, margin: 0, font: `${pt(13)} var(--font-ui)`, color: FAINT_INK }}>
      {tr('ESC 키를 눌러도 바로 돌아가요.')}
    </p>
  </section>;
}

/** Fills whatever box the gallery gives it and lays the screen out at that size,
 * the way the renderer lays out at the display it was handed. Measuring instead
 * of reading the viewport keeps the example banner above it out of the sums. */
export function PairingCeremony({ screen, boot = 'manufacturer' }: { screen: CeremonyScreen; boot?: CeremonyBoot }) {
  const frame = useRef<HTMLDivElement>(null);
  const [box, setBox] = useState<{ width: number; height: number } | null>(null);
  useLayoutEffect(() => {
    const element = frame.current;
    if (!element) return undefined;
    const measure = () => { setBox({ width: element.clientWidth, height: element.clientHeight }); };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => { observer.disconnect(); };
  }, []);
  return <div ref={frame} data-pairing-ceremony={screen} dir={currentLocale() === 'ar' ? 'rtl' : 'ltr'} style={{
    height: '100%', background: BACKGROUND, position: 'relative', overflow: 'hidden',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
  }}>
    <div style={{ position: 'absolute', insetInlineStart: 28, top: 24 }}>
      <Signature size={36} room={box === null ? 0
        : Math.trunc((box.width - Math.min(Math.trunc((box.width * 72) / 100), 760)) / 2) - 28 - 36 - 9 - 9} />
    </div>
    {box === null ? null : screen === 'introduction'
      ? <Introduction width={box.width} />
      : screen === 'comparison'
        ? <Comparison width={box.width} height={box.height} boot={boot} />
        : <Invitation width={box.width} height={box.height} />}
  </div>;
}
