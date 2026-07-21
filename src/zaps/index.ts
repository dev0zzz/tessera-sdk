/**
 * tessera-sdk/zaps — the zap button any Tessera app can embed in minutes.
 *
 * A zap is a small public USDC payment between Tessera users. The host app
 * needs ZERO auth or wallet integration: everything (session, recipient
 * lookup, amount presets, passkey signature, rail submission, record write)
 * happens inside a popup on tessera.at. This module only opens the popup,
 * speaks the `tessera-zap/1` postMessage protocol and returns the receipt.
 *
 * Browser-only. Framework stories:
 *  - Vite/vanilla: `import 'tessera-sdk/zaps'` + `<tessera-zap-button …>`
 *  - React/Next:   dynamically import inside a client component, same element
 *  - Astro/static: a module <script> that imports this package
 */

export const ZAP_PROTOCOL = 'tessera-zap/1';

/** Default popup host — override via openZap({ zapUrl }) for testing. */
export const DEFAULT_ZAP_URL = 'https://tessera.at/zap';

export interface ZapRequest {
  /** Recipient DID (did:plc:… / did:web:…). */
  to: string;
  /** Optional at:// URI of the zapped content (post, score, photo…). */
  ref?: string;
  /** Optional preselected amount in micro-USD (1 USDC = 1_000_000). */
  amountUsd?: number;
  /** Popup base URL override (e.g. a staging host). */
  zapUrl?: string;
}

export interface ZapReceipt {
  /** at:// URI of the at.tessera.zap.payment record in the SENDER's repo. */
  recordUri: string;
  /** Paid amount in micro-USD. */
  amountUsd: number;
  /** Rail-specific transaction reference (verifiable by third parties). */
  railRef: string;
}

/** Thrown when the user closes the popup / cancels — an abort, not an error. */
export class ZapAbortError extends Error {
  constructor() {
    super('Zap abgebrochen');
    this.name = 'ZapAbortError';
  }
}

type PopupMsg = {
  protocol?: string;
  type?: string;
  recordUri?: string;
  amountUsd?: number;
  railRef?: string;
  message?: string;
};

/**
 * Opens the zap popup for `to` and resolves with the receipt once the user
 * completed the payment (or rejects with ZapAbortError / Error).
 * MUST be called synchronously from a user gesture (click handler), or the
 * browser will block the popup.
 */
export function openZap(request: ZapRequest): Promise<ZapReceipt> {
  const base = request.zapUrl ?? DEFAULT_ZAP_URL;
  const origin = new URL(base).origin;
  const params = new URLSearchParams({ to: request.to });
  if (request.ref) params.set('ref', request.ref);
  if (request.amountUsd && request.amountUsd > 0) {
    params.set('amountUsd', String(Math.floor(request.amountUsd)));
  }
  const win = window.open(
    `${base}?${params}`,
    'tessera-zap',
    'width=420,height=640',
  );

  return new Promise<ZapReceipt>((resolve, reject) => {
    if (!win) {
      reject(new Error('Popup blockiert — bitte Popups für diese Seite erlauben'));
      return;
    }
    // Catch the user closing the popup (incl. cancelling the passkey via OS
    // UI) instead of hanging forever.
    const closePoll = window.setInterval(() => {
      if (win.closed) {
        cleanup();
        reject(new ZapAbortError());
      }
    }, 500);
    const onMsg = (event: MessageEvent) => {
      if (event.origin !== origin) return;
      const d = event.data as PopupMsg;
      if (d?.protocol !== ZAP_PROTOCOL) return;
      if (d.type === 'receipt') {
        if (
          typeof d.recordUri === 'string' &&
          typeof d.amountUsd === 'number' &&
          typeof d.railRef === 'string'
        ) {
          cleanup();
          resolve({
            recordUri: d.recordUri,
            amountUsd: d.amountUsd,
            railRef: d.railRef,
          });
        }
      } else if (d.type === 'cancel') {
        cleanup();
        reject(new ZapAbortError());
      } else if (d.type === 'error') {
        cleanup();
        reject(new Error(d.message ?? 'Zap fehlgeschlagen'));
      }
    };
    const cleanup = () => {
      window.clearInterval(closePoll);
      window.removeEventListener('message', onMsg);
    };
    window.addEventListener('message', onMsg);
  });
}
