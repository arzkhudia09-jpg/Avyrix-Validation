/* ============================================================
   app.js — Global JavaScript for Avyrix
   Handles: navigation, scroll effects, shared UI
   ============================================================ */

(function () {
  'use strict';

  /* ── Active nav link highlighting ─────────────────────── */
  function setActiveNav() {
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.nav__links a').forEach(link => {
      const href = link.getAttribute('href');
      if (href === currentPage || (currentPage === '' && href === 'index.html')) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });
  }

  /* ── Scroll-based nav shadow ──────────────────────────── */
  function initNavScroll() {
    const nav = document.querySelector('.nav');
    if (!nav) return;
    const handler = () => {
      nav.style.background = window.scrollY > 20
        ? 'rgba(8,11,16,0.95)'
        : 'rgba(8,11,16,0.8)';
    };
    window.addEventListener('scroll', handler, { passive: true });
    handler();
  }

  /* ── Intersection Observer: fade-up on scroll ─────────── */
  function initScrollReveal() {
    const targets = document.querySelectorAll('[data-reveal]');
    if (!targets.length) return;
    const obs = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.style.opacity = '1';
          entry.target.style.transform = 'translateY(0)';
          obs.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

    targets.forEach((el, i) => {
      el.style.cssText = `opacity:0;transform:translateY(24px);transition:opacity 0.6s cubic-bezier(0.4,0,0.2,1) ${i * 0.08}s, transform 0.6s cubic-bezier(0.4,0,0.2,1) ${i * 0.08}s;`;
      obs.observe(el);
    });
  }

  /* ── Animated counter (for stat numbers) ─────────────── */
  function animateCounter(el, target, duration) {
    const start = performance.now();
    const startVal = 0;
    const update = (now) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(startVal + (target - startVal) * eased);
      el.textContent = current.toLocaleString();
      if (progress < 1) requestAnimationFrame(update);
    };
    requestAnimationFrame(update);
  }

  function initCounters() {
    const counters = document.querySelectorAll('[data-count]');
    if (!counters.length) return;
    const obs = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const target = parseInt(entry.target.dataset.count, 10);
          animateCounter(entry.target, target, 1400);
          obs.unobserve(entry.target);
        }
      });
    }, { threshold: 0.5 });
    counters.forEach(c => obs.observe(c));
  }

  /* ── Typewriter effect for hero ───────────────────────── */
  function initTypewriter() {
    const el = document.getElementById('typewriter');
    if (!el) return;
    const phrases = ['SQL Injection', 'XSS Attacks', 'Secret Leaks', 'IDOR Issues', 'Broken Auth'];
    let phraseIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    let isPaused = false;

    const type = () => {
      const current = phrases[phraseIndex];
      if (isPaused) {
        setTimeout(type, 1200);
        isPaused = false;
        return;
      }
      if (!isDeleting) {
        charIndex++;
        el.textContent = current.slice(0, charIndex);
        if (charIndex === current.length) {
          isPaused = true;
          isDeleting = true;
          setTimeout(type, 800);
          return;
        }
      } else {
        charIndex--;
        el.textContent = current.slice(0, charIndex);
        if (charIndex === 0) {
          isDeleting = false;
          phraseIndex = (phraseIndex + 1) % phrases.length;
        }
      }
      setTimeout(type, isDeleting ? 50 : 90);
    };
    type();
  }

  /* ── Mobile nav toggle ────────────────────────────────── */
  function initMobileNav() {
    const toggle = document.getElementById('nav-toggle');
    const menu = document.querySelector('.nav__mobile-menu');
    if (!toggle || !menu) return;
    toggle.addEventListener('click', () => {
      const open = menu.style.display === 'flex';
      menu.style.display = open ? 'none' : 'flex';
      toggle.setAttribute('aria-expanded', String(!open));
    });
  }

  /* ── Init all ─────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', () => {
    setActiveNav();
    initNavScroll();
    initScrollReveal();
    initCounters();
    initTypewriter();
    initMobileNav();
  });
})();
