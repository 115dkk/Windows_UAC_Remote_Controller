// SPDX-License-Identifier: GPL-2.0-or-later
// The pinned rust-analyzer CLI returns success for warnings. This adapter must not.
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repository = fileURLToPath(new URL('../', import.meta.url));

export function pinnedToolchain(root = repository) {
  const manifest = readFileSync(resolve(root, 'rust-toolchain.toml'), 'utf8');
  const channels = [...manifest.matchAll(/^channel\s*=\s*"(\d+\.\d+\.\d+)"\s*$/gm)];
  if (channels.length !== 1) {
    throw new Error('rust-toolchain.toml must pin one exact stable toolchain version.');
  }
  return channels[0][1];
}

/**
 * Match this gate's explicit Cargo dev profile without changing the parent env.
 * RA 1.97 CLI queries cfg using `cargo rustc --print cfg -- -O`, but unlike its
 * LSP configuration it does not add the debug_assertions cfg override. A real
 * rustc codegen flag keeps that query consistent with the dev-built proc macros.
 * Encoded flags have Cargo precedence, including an explicitly empty value.
 */
export function buildAnalyzerEnvironment(incoming, platform = 'posix') {
  const environment = { ...incoming };
  // Windows environment names are case-insensitive. Reuse the existing spelling
  // rather than adding a duplicate that Node could discard when spawning.
  const keyFor = (name) => platform === 'win32'
    ? Object.keys(incoming).sort().find((key) => key.toUpperCase() === name) ?? name
    : name;
  const encodedKey = keyFor('CARGO_ENCODED_RUSTFLAGS');
  const plainKey = keyFor('RUSTFLAGS');
  const flag = '-Cdebug-assertions=yes';
  if (incoming[encodedKey] !== undefined) {
    const existing = incoming[encodedKey];
    environment[encodedKey] = existing ? `${existing}\u001f${flag}` : flag;
  } else {
    const existing = incoming[plainKey];
    environment[plainKey] = existing ? `${existing} ${flag}` : flag;
  }
  return environment;
}

/** Classify actual CLI output; a warning-only exit 0 is still a failed gate. */
export function classifyDiagnostics(result) {
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`
    .replace(/\u001b\[[0-9;]*[A-Za-z]/g, '');
  const reasons = [];
  if (result.error) reasons.push(`could not finish analyzer: ${result.error.message}`);
  if (result.signal) reasons.push(`analyzer terminated by ${result.signal}`);
  if (result.status !== 0) reasons.push(`analyzer exit status: ${String(result.status)}`);
  if (!/^diagnostic scan complete\s*$/m.test(output)) {
    reasons.push('analyzer did not report a completed scan');
  }
  // At the pinned version every reported diagnostic begins with "at crate".
  // Fail on an unfamiliar severity too, instead of silently accepting format drift.
  const reportedDiagnostics = output.split(/\r?\n/)
    .map((line) => line.match(/\bat crate\s.+/)?.[0])
    .filter((line) => line !== undefined);
  // Native CLI calls LSP Hints "WeakWarning". Only cfg branch shading is
  // informational here; every other diagnostic, including other hints, fails.
  // Keep this exact and visible, never a blanket WeakWarning/Warning exclusion.
  const isInactiveHint = (line) => line.includes(': WeakWarning Ra("inactive-code", WeakWarning) from ')
    && line.includes(': code is inactive due to #[cfg] directives:');
  const configurationHints = reportedDiagnostics.filter(isInactiveHint);
  const diagnostics = reportedDiagnostics.filter((line) => !isInactiveHint(line));
  if (diagnostics.length > 0) reasons.push(`${diagnostics.length} analyzer diagnostic(s)`);
  if (/\b(?:WARN|ERROR)\b|^\s*(?:error|warning)(?:\[|:)/m.test(output)) {
    reasons.push('analyzer or workspace-loading warning/error');
  }
  return { ok: reasons.length === 0, reasons, diagnostics, configurationHints, output, processStatus: result.status };
}

export function scanWorkspace(workspace = repository) {
  const toolchain = pinnedToolchain();
  const result = spawnSync(
    'rustup',
    ['run', toolchain, 'rust-analyzer', '--quiet', 'diagnostics', '--severity', 'weak', resolve(workspace)],
    {
      cwd: workspace,
      env: buildAnalyzerEnvironment(process.env, process.platform),
      encoding: 'utf8',
      timeout: 600_000,
      maxBuffer: 32 * 1024 * 1024,
    },
  );
  return classifyDiagnostics(result);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = scanWorkspace();
  const reportDirectory = resolve(repository, 'target', 'quality');
  mkdirSync(reportDirectory, { recursive: true });
  writeFileSync(resolve(reportDirectory, 'rust-analyzer.txt'), result.output);
  if (!result.ok) {
    process.stdout.write(result.output);
    process.stderr.write(`Rust Analyzer gate failed: ${result.reasons.join('; ')}\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`Rust Analyzer gate: no errors or warnings; ${result.configurationHints.length} inactive-code hints recorded separately.\n`);
  }
}
