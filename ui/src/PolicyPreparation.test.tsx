// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic state presentation; native minified-release behavior is checked in CI.
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { App } from './App';
import { ko } from './messages.ko';
import { createQaBridge, qaCase } from './qa-fixtures';

describe('notification settings distinguish owner preparation from policy read failure', () => {
  it.each([
    ['phone-service-stopped', ko.policyStoppedTitle],
    ['phone-service-preparing', ko.policyPreparingTitle],
    ['phone-service-waiting-unlock', ko.policyUnlockTitle],
    ['phone-service-cleanup', ko.policyCleanupTitle],
    ['phone-service-unavailable', ko.policyOwnerUnavailableTitle],
  ])('uses the actual preparation state for %s', async (fixture, title) => {
    render(<App bridge={createQaBridge(qaCase(fixture).snapshot)} initialPage="schedule" />);
    expect(await screen.findByRole('heading', { name: title })).toBeVisible();
    expect(screen.queryByRole('heading', { name: ko.policyUnavailableTitle })).not.toBeInTheDocument();
    expect(screen.queryByRole('radio')).not.toBeInTheDocument();
  });
  it('reserves the settings read error for an already-ready owner with a missing policy', async () => {
    const snapshot = { ...qaCase('phone-service-ready').snapshot, policy: null };
    render(<App bridge={createQaBridge(snapshot)} initialPage="schedule" />);
    expect(await screen.findByRole('heading', { name: ko.policyUnavailableTitle })).toBeVisible();
    expect(screen.queryByRole('radio')).not.toBeInTheDocument();
  });
});
