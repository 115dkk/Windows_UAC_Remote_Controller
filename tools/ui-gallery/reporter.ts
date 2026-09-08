// SPDX-License-Identifier: GPL-2.0-or-later
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { arch, platform, release } from 'node:os';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FullConfig, FullResult, Reporter, TestCase, TestResult } from '@playwright/test/reporter';
import { galleryCases } from './cases';

const root = fileURLToPath(new URL('../../', import.meta.url));
const output = resolve(root, 'target/ui-gallery');
const require = createRequire(import.meta.url);
const escapeHtml = (value: unknown): string => String(value).replace(/[&<>"']/gu, (character) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[character] ?? character);
const linkPath = (path: string): string => path.split('/').map(encodeURIComponent).join('/');

interface Attachment { name: string; type: string; path: string }
interface Attempt {
  status: string;
  retry: number;
  durationMillis: number;
  errors: string[];
  attachments: Attachment[];
  observation: unknown;
}

/** Actual runner results, not visual approval or native-platform certification. */
export default class GalleryReporter implements Reporter {
  private config: FullConfig | null = null;
  private readonly results = new Map<string, Attempt[]>();
  private readonly runnerErrors: string[] = [];
  private readonly artifactErrors: string[] = [];

  constructor(private readonly options: { runId: string }) {}

  onBegin(config: FullConfig): void { this.config = config; }
  onError(error: { message?: string }): void {
    if (this.runnerErrors.length < 20) this.runnerErrors.push((error.message ?? 'Runner error without a message').slice(0, 4000));
  }

  onTestEnd(test: TestCase, result: TestResult): void {
    const attachments: Attachment[] = [];
    let observation: unknown = null;
    for (const attachment of result.attachments) {
      if (attachment.path) {
        const path = relative(output, resolve(attachment.path));
        if (isAbsolute(path) || path === '..' || path.startsWith(`..${sep}`)) {
          this.artifactErrors.push(`Attachment outside gallery directory: ${attachment.name}`);
          continue;
        }
        attachments.push({ name: attachment.name, type: attachment.contentType, path: path.split(sep).join('/') });
      }
      if (attachment.name === 'gallery-observation') {
        try {
          const bytes = attachment.body ?? (attachment.path ? readFileSync(attachment.path) : null);
          if (!bytes || bytes.length > 256 * 1024) throw new Error('Missing or excessive gallery observation.');
          observation = JSON.parse(bytes.toString('utf8')) as unknown;
        } catch {
          this.artifactErrors.push(`Unreadable observation for ${test.title}`);
        }
      }
    }
    const attempts = this.results.get(test.title) ?? [];
    attempts.push({
      status: result.status, retry: result.retry, durationMillis: result.duration,
      errors: result.errors.map((error) => (error.message ?? 'Test error without a message').slice(0, 6000)),
      attachments, observation,
    });
    this.results.set(test.title, attempts);
  }

  async onEnd(result: FullResult): Promise<void | { status: 'failed' }> {
    mkdirSync(output, { recursive: true });
    let build: unknown = null;
    try {
      const candidate = JSON.parse(readFileSync(resolve(output, 'build-input.json'), 'utf8')) as { runId?: unknown };
      if (candidate.runId !== this.options.runId) throw new Error('Stale build provenance.');
      build = candidate;
    } catch {
      this.artifactErrors.push('Current-run compiled-QA/HEAD provenance is unavailable; do not treat old files as this run.');
    }
    const packageData = JSON.parse(readFileSync(require.resolve('@playwright/test/package.json'), 'utf8')) as { version?: unknown };
    const rows = galleryCases.map((selected) => ({ ...selected, attempts: this.results.get(selected.id) ?? [] }));
    if (rows.some((row) => row.attempts.length === 0)) this.artifactErrors.push('The full declared gallery did not execute.');
    const finalStatus = this.artifactErrors.length > 0 ? 'failed' : result.status;
    const manifest = {
      schemaVersion: 1, runId: this.options.runId, generatedAt: new Date().toISOString(),
      scope: 'CLIENT / SYNTHETIC', visualReview: 'ROOT_REQUIRED_NOT_PERFORMED_BY_HARNESS',
      limitations: ['Not native shell/UAC Secure Desktop evidence', 'Not Android Keystore/auth/notification or package-lifecycle evidence', 'Not latency, OS delivery, approval, or pixel-baseline proof'],
      runnerStatus: result.status, finalStatus, expectedCases: galleryCases.length, executedCases: this.results.size,
      environment: { os: platform(), osRelease: release(), architecture: arch(), node: process.version,
        playwright: typeof packageData.version === 'string' ? packageData.version : null,
        browser: 'chromium', locale: 'ko-KR', timezone: 'Asia/Seoul', reducedMotion: 'reduce',
        workers: this.config?.workers ?? null, retriesConfigured: this.config?.projects.map((project) => project.retries) ?? [] },
      build, runnerErrors: this.runnerErrors, artifactErrors: this.artifactErrors, cases: rows,
    };
    writeFileSync(resolve(output, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    const cards = rows.map((row) => {
      const attempts = row.attempts.map((attempt) => {
        const pictures = attempt.attachments.filter((attachment) => attachment.type === 'image/png').map((attachment) =>
          `<figure><a href="${linkPath(attachment.path)}"><img src="${linkPath(attachment.path)}" alt="CLIENT SYNTHETIC ${escapeHtml(row.id)} ${escapeHtml(attachment.name)}" loading="lazy"></a><figcaption>${escapeHtml(attachment.name)}</figcaption></figure>`).join('');
        const files = attempt.attachments.map((attachment) => `<li><a href="${linkPath(attachment.path)}">${escapeHtml(attachment.name)}</a></li>`).join('');
        return `<p>실행기 상태: ${escapeHtml(attempt.status)} · 시도 ${String(attempt.retry + 1)}</p>${pictures || '<p>이 시도의 이미지 없음. 실패/설정 기록을 확인하세요.</p>'}<details><summary>관찰·콘솔·실패·첨부 파일</summary><pre>${escapeHtml(JSON.stringify({ errors: attempt.errors, observation: attempt.observation }, null, 2))}</pre><ul>${files}</ul></details>`;
      }).join('');
      return `<section><h2>${escapeHtml(row.id)}</h2><p>${escapeHtml(row.fixture)} · ${String(row.viewport.width)}×${String(row.viewport.height)} · ${escapeHtml(row.colorScheme)} · forced-colors ${escapeHtml(row.forcedColors)}</p>${attempts || '<p>실행되지 않음. 캡처/검수 증거가 없습니다.</p>'}</section>`;
    }).join('');
    writeFileSync(resolve(output, 'index.html'), `<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CLIENT · SYNTHETIC 갤러리</title><style>body{margin:0;padding:24px;background:#f2f6f7;color:#152c35;font:16px/1.6 system-ui,sans-serif}header,section{max-width:1280px;margin:0 auto 24px;padding:20px;background:#fbfdfd;border:1px solid #d4e0e5;border-radius:12px}h1,h2{overflow-wrap:anywhere}h2{font-size:18px}a{color:#0b7285}figure{display:inline-block;vertical-align:top;margin:12px 16px 12px 0;max-width:100%;width:420px}img{display:block;width:100%;height:auto;border:1px solid #d4e0e5}pre{white-space:pre-wrap;overflow-wrap:anywhere}summary{cursor:pointer}a:focus-visible,summary:focus-visible{outline:3px solid #0b7285;outline-offset:3px}</style><header><h1>CLIENT · SYNTHETIC 화면 갤러리</h1><p>화면 예시 · 실제 연결 아님. 자동 실행 결과는 시각 검수나 네이티브 서비스·UAC·휴대폰 인증의 성공 증거가 아닙니다.</p><p>ROOT가 실제 이미지와 화면 상태를 검토해야 합니다. 실패 이미지·trace도 첨부 파일로 보존됩니다.</p><p><a href="manifest.json">JSON 매니페스트</a> · 갤러리 최종 상태: ${escapeHtml(finalStatus)} · 실행 ${String(this.results.size)}/${String(galleryCases.length)}</p><details><summary>빌드·HEAD·환경·실행 실패</summary><pre>${escapeHtml(JSON.stringify({ build, environment: manifest.environment, runnerErrors: this.runnerErrors, artifactErrors: this.artifactErrors }, null, 2))}</pre></details></header>${cards}</html>\n`);
    if (this.artifactErrors.length > 0) return { status: 'failed' };
  }
}
