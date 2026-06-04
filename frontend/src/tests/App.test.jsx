import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, fireEvent } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../App';

vi.mock('../ThreatGlobe', () => ({
  default: () => <div data-testid="threat-globe" />
}));

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (url) => {
    if (String(url).includes('/api/v1/auth/session')) {
      return { ok: true, json: async () => ({ authenticated: false }) };
    }
    if (String(url).includes('/api/metrics/benchmarks')) {
      return { ok: true, json: async () => ({ labels: [], agentic_ids: [] }) };
    }
    return { ok: false, status: 401, json: async () => ({ error: 'Unauthorized' }) };
  }));

  Object.defineProperty(window, 'speechSynthesis', {
    configurable: true,
    value: {
      cancel: vi.fn(),
      getVoices: vi.fn(() => []),
      speak: vi.fn()
    }
  });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('App shell', () => {
  it('renders the dashboard and access gate', async () => {
    render(<App />);

    expect(await screen.findByText(/Unlock SOC Console/i)).toBeInTheDocument();
    expect(screen.getByText(/THREAT DASHBOARD/i)).toBeInTheDocument();
    expect(screen.getByText(/ACTIVE THREAT FEED/i)).toBeInTheDocument();
  });

  it('opens the attack simulator from the threat map', async () => {
    render(<App />);

    fireEvent.click(screen.getByText('Threat Map'));
    expect(screen.getByTestId('threat-globe')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /SIMULATE ATTACK/i }));
    expect(screen.getByText(/ATTACK SIMULATOR/i)).toBeInTheDocument();
  });
});
