// SPDX-License-Identifier: GPL-2.0-or-later
// QA-ONLY drawing of the native Windows pairing ceremony, for the synthetic
// gallery. The real screens are painted by GDI in
// crates/windows-service-host/src/ffi/pairing_client/renderer_ui.rs on a private
// desktop. This is a client mock at the same geometry and copy so the layout can
// be reviewed; it is never native proof, and it holds no invitation.
import { useId, useLayoutEffect, useRef, useState } from 'react';
import { tr } from './i18n';
import { sampleQrModules, sampleQrWidth } from './pairing-ceremony-sample';

export type CeremonyScreen = 'introduction' | 'invitation';

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

function Signature({ size }: { size: number }) {
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
    <span style={{ font: `${pt(16)} var(--font-ui)`, color: ACCENT }}>{tr('UAC 원격 승인')}</span>
  </div>;
}

function Button({ label, primary }: { label: string; primary?: boolean }) {
  return <button type="button" disabled style={{
    minWidth: primary === undefined ? 300 : 184, height: primary === undefined ? 56 : 60,
    font: `${pt(16)} var(--font-ui)`, color: INK, background: '#fdfdfd',
    border: `1px solid ${primary ? ACCENT : '#adadad'}`, boxShadow: primary ? `0 0 0 1px ${ACCENT}` : 'none',
    borderRadius: 3, padding: '0 16px',
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
      {tr('QR 코드로 이 컴퓨터에 휴대폰을 등록하는 절차입니다. 휴대폰에서 QR 코드 연결을 켠 다음 진행해 주세요.')}
    </p>
    <p style={{ margin: `20px 0 0`, font: `${pt(16)} var(--font-ui)`, color: MUTED_INK }}>
      {tr('ESC를 누르거나 [취소]를 눌러 언제든 중지할 수 있습니다.')}
    </p>
    <p style={{
      margin: `26px 0 0`, padding: '20px 24px', background: CAUTION_SURFACE,
      font: `${pt(16)} var(--font-ui)`, color: CAUTION_INK,
    }}>{tr('주의: 다른 사람의 요청으로 이 절차에 들어왔다면 지금 바로 중지하세요. QR 코드를 다른 사람에게 절대 공유하지 마세요.')}</p>
    <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginTop: 32 }}>
      <Button label={tr('QR 코드 보기')} primary />
      <Button label={tr('취소')} primary={false} />
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
export function PairingCeremony({ screen }: { screen: CeremonyScreen }) {
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
  return <div ref={frame} data-pairing-ceremony={screen} style={{
    height: '100%', background: BACKGROUND, position: 'relative', overflow: 'hidden',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
  }}>
    <div style={{ position: 'absolute', left: 28, top: 24 }}><Signature size={36} /></div>
    {box === null ? null : screen === 'introduction'
      ? <Introduction width={box.width} />
      : <Invitation width={box.width} height={box.height} />}
  </div>;
}
