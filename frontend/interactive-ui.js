(() => {
  const finePointer = window.matchMedia('(pointer:fine)').matches;
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const ambient = document.createElement('div');
  ambient.className = 'ambient-layer';
  document.body.prepend(ambient);

  if (finePointer && !reduced) {
    const glow = document.createElement('div');
    glow.className = 'cursor-glow';
    document.body.appendChild(glow);
    window.addEventListener('pointermove', (e) => {
      glow.style.left = `${e.clientX}px`;
      glow.style.top = `${e.clientY}px`;
    }, { passive: true });
  }

  const tiltTargets = () => document.querySelectorAll('.login-card, .dashboard-card, .panel');

  function enableTilt(el) {
    if (!finePointer || reduced || el.dataset.tiltReady) return;
    el.dataset.tiltReady = '1';
    el.classList.add('interactive-tilt');
    el.addEventListener('pointermove', (e) => {
      const r = el.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width - .5;
      const y = (e.clientY - r.top) / r.height - .5;
      el.style.transform = `perspective(900px) rotateX(${-y * 4}deg) rotateY(${x * 5}deg) translateY(-3px)`;
    });
    el.addEventListener('pointerleave', () => {
      el.style.transform = '';
    });
  }

  function bindTilt() {
    tiltTargets().forEach(enableTilt);
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: .12 });

  function bindReveal() {
    document.querySelectorAll('.dashboard-card, .panel, .feature').forEach((el, i) => {
      if (el.dataset.revealReady) return;
      el.dataset.revealReady = '1';
      el.classList.add('reveal-item');
      el.style.transitionDelay = `${Math.min(i % 4, 3) * 70}ms`;
      observer.observe(el);
    });
  }

  function bindRipples() {
    document.querySelectorAll('button').forEach((button) => {
      if (button.dataset.rippleReady) return;
      button.dataset.rippleReady = '1';
      button.addEventListener('click', (e) => {
        const r = button.getBoundingClientRect();
        const d = Math.max(r.width, r.height);
        const wave = document.createElement('span');
        wave.className = 'ripple-wave';
        wave.style.width = wave.style.height = `${d}px`;
        wave.style.left = `${e.clientX - r.left - d / 2}px`;
        wave.style.top = `${e.clientY - r.top - d / 2}px`;
        button.appendChild(wave);
        setTimeout(() => wave.remove(), 650);
      });
    });
  }

  function bindNavState() {
    document.querySelectorAll('.nav-button:not(.logout)').forEach((button) => {
      if (button.dataset.navReady) return;
      button.dataset.navReady = '1';
      button.addEventListener('click', () => {
        document.querySelectorAll('.nav-button:not(.logout)').forEach((b) => b.classList.remove('active'));
        button.classList.add('active');
      });
    });
  }

  function refreshInteractiveUI() {
    bindTilt();
    bindReveal();
    bindRipples();
    bindNavState();
  }

  document.addEventListener('DOMContentLoaded', refreshInteractiveUI);

  const mutationObserver = new MutationObserver(() => refreshInteractiveUI());
  mutationObserver.observe(document.documentElement, { childList: true, subtree: true });
})();
