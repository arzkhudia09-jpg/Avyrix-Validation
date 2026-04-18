/* ============================================================
   utils.js — Shared utility functions for Avyrix
   ============================================================ */

/**
 * Sanitize a string for safe insertion as text content.
 * Never insert this into innerHTML — always use textContent.
 * @param {string} str - Raw user input
 * @returns {string} Trimmed, safe string
 */
function sanitizeInput(str) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, 50000); // Hard limit for code input
}

/**
 * Escape HTML entities — only used for building safe display strings
 * that will be placed via textContent anyway.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(str).replace(/[&<>"']/g, m => map[m]);
}

/**
 * Validate email format
 * @param {string} email
 * @returns {boolean}
 */
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim());
}

/**
 * Validate name — letters, spaces, hyphens only, 2–60 chars
 * @param {string} name
 * @returns {boolean}
 */
function isValidName(name) {
  return /^[A-Za-z\s\-]{2,60}$/.test(name.trim());
}

/**
 * Copy text to clipboard safely, falling back to execCommand
 * @param {string} text - Text to copy
 * @param {HTMLElement} btn - Button element to show feedback on
 */
async function copyToClipboard(text, btn) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      // Fallback: textarea trick (no innerHTML used)
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:absolute;left:-9999px;top:-9999px;';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    if (btn) {
      btn.classList.add('copied');
      const original = btn.textContent;
      btn.textContent = '✓ Copied!';
      setTimeout(() => {
        btn.classList.remove('copied');
        btn.textContent = original;
      }, 2000);
    }
  } catch (err) {
    console.error('Copy failed:', err);
  }
}

/**
 * Create a DOM element safely with text content
 * @param {string} tag
 * @param {string} className
 * @param {string} [text]
 * @returns {HTMLElement}
 */
function el(tag, className, text) {
  const elem = document.createElement(tag);
  if (className) elem.className = className;
  if (text !== undefined) elem.textContent = text; // textContent, never innerHTML
  return elem;
}

/**
 * Set error state on a form field
 * @param {HTMLElement} input
 * @param {string} message
 */
function setFieldError(input, message) {
  input.style.borderColor = 'var(--accent-red)';
  input.style.boxShadow = '0 0 0 3px var(--accent-red-dim)';
  let errEl = input.parentElement.querySelector('.field-error');
  if (!errEl) {
    errEl = document.createElement('span');
    errEl.className = 'field-error';
    errEl.style.cssText = 'font-size:12px;color:var(--accent-red);font-family:var(--font-mono);';
    input.parentElement.appendChild(errEl);
  }
  errEl.textContent = message; // textContent only
}

/**
 * Clear error state on a form field
 * @param {HTMLElement} input
 */
function clearFieldError(input) {
  input.style.borderColor = '';
  input.style.boxShadow = '';
  const errEl = input.parentElement.querySelector('.field-error');
  if (errEl) errEl.remove();
}

/**
 * Debounce a function
 * @param {Function} fn
 * @param {number} delay
 * @returns {Function}
 */
function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}
