import {
  DEFAULT_ZAP_URL,
  ZapAbortError,
  type ZapReceipt,
  openZap,
} from './index.js';

/**
 * Browser-only entry: importing this module registers the
 * <tessera-zap-button> custom element. Do NOT import during SSR — in React
 * frameworks import it inside a client component effect:
 *   useEffect(() => { void import('@tesseraat/sdk/zaps/element') }, [])
 */

void DEFAULT_ZAP_URL; // re-exported below for element consumers
export { openZap, ZapAbortError, DEFAULT_ZAP_URL };
export type { ZapReceipt };

/**
 * `<tessera-zap-button did="did:plc:…" ref="at://…" amount-usd="500000">`
 *
 * Renders a ⚡-button; on click it opens the zap popup. Emits:
 *  - 'zap'       CustomEvent<ZapReceipt> on success
 *  - 'zap-error' CustomEvent<{ message: string }> on failure (not on abort)
 * Attributes: did (required), ref, amount-usd, zap-url, label.
 */
export class TesseraZapButton extends HTMLElement {
  private button: HTMLButtonElement;

  constructor() {
    super();
    const root = this.attachShadow({ mode: 'open' });
    const style = document.createElement('style');
    style.textContent = `
      button {
        display: inline-flex; align-items: center; gap: 0.35em;
        font: inherit; cursor: pointer;
        padding: 0.35em 0.8em; border-radius: 999px;
        border: 1px solid #e8be62; background: rgba(232, 190, 98, 0.12);
        color: #e8be62; transition: background 150ms, transform 150ms;
      }
      button:hover { background: rgba(232, 190, 98, 0.25); }
      button:active { transform: scale(0.96); }
      button:disabled { opacity: 0.5; cursor: default; }
    `;
    this.button = document.createElement('button');
    this.button.type = 'button';
    this.button.addEventListener('click', () => this.zap());
    root.append(style, this.button);
  }

  connectedCallback() {
    this.render();
  }

  static get observedAttributes() {
    return ['label', 'did'];
  }

  attributeChangedCallback() {
    this.render();
  }

  private render() {
    this.button.textContent = `⚡ ${this.getAttribute('label') ?? 'Zap'}`;
    this.button.disabled = !this.getAttribute('did');
  }

  private zap() {
    const to = this.getAttribute('did');
    if (!to) return;
    const amountAttr = this.getAttribute('amount-usd');
    openZap({
      to,
      ref: this.getAttribute('ref') ?? undefined,
      amountUsd: amountAttr ? Number(amountAttr) : undefined,
      zapUrl: this.getAttribute('zap-url') ?? undefined,
    }).then(
      (receipt) => {
        this.dispatchEvent(
          new CustomEvent<ZapReceipt>('zap', { detail: receipt, bubbles: true }),
        );
      },
      (err: unknown) => {
        if (err instanceof ZapAbortError) return;
        this.dispatchEvent(
          new CustomEvent('zap-error', {
            detail: { message: err instanceof Error ? err.message : 'Zap fehlgeschlagen' },
            bubbles: true,
          }),
        );
      },
    );
  }
}

// Idempotent registration: importing this module anywhere defines the element.
if (typeof customElements !== 'undefined' && !customElements.get('tessera-zap-button')) {
  customElements.define('tessera-zap-button', TesseraZapButton);
}
