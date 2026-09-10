(() => {
  const finePointer = window.matchMedia('(pointer:fine)').matches;
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const ambient = document.createElement('div');
  ambient.className = 'ambient-layer';
  document.body.prepend(ambient);

  const scene = document.createElement('div');
  scene.className = 'immersive-scene';
  scene.innerHTML = '<div class="cyber-grid"></div><div class="particle-field"></div>';
  document.body.prepend(scene);

  const particleField = scene.querySelector('.particle-field');
  if (!reduced) {
    for (let i = 0; i < 24; i++) {
      const p = document.createElement('span');
      p.className = 'particle';
      p.style.left = `${Math.random() * 100}%`;
      p.style.top = `${Math.random() * 100}%`;
      p.style.setProperty('--dur', `${7 + Math.random() * 8}s`);
      p.style.setProperty('--dx', `${-30 + Math.random() * 60}px`);
      p.style.setProperty('--z', `${Math.round(Math.random() * 90)}px`);
      p.style.animationDelay = `${-Math.random() * 8}s`;
      particleField.appendChild(p);
    }
  }

  let glow;
  let ring;
  if (finePointer && !reduced) {
    glow = document.createElement('div');
    glow.className = 'cursor-glow';
    ring = document.createElement('div');
    ring.className = 'cursor-ring';
    document.body.append(glow, ring);

    let gx = innerWidth / 2, gy = innerHeight / 2;
    let rx = gx, ry = gy;
    window.addEventListener('pointermove', (e) => {
      gx = e.clientX;
      gy = e.clientY;
      glow.style.left = `${gx}px`;
      glow.style.top = `${gy}px`;
    }, { passive: true });

    const tick = () => {
      rx += (gx - rx) * .16;
      ry += (gy - ry) * .16;
      ring.style.left = `${rx}px`;
      ring.style.top = `${ry}px`;
      requestAnimationFrame(tick);
    };
    tick();
  }

  function enableTilt(el) {
    if (!finePointer || reduced || el.dataset.tiltReady) return;
    el.dataset.tiltReady = '1';
    el.classList.add('interactive-tilt', 'spotlight-card');
    el.addEventListener('pointermove', (e) => {
      const r = el.getBoundingClientRect();
      const px = (e.clientX - r.left) / r.width;
      const py = (e.clientY - r.top) / r.height;
      const x = px - .5;
      const y = py - .5;
      el.style.setProperty('--sx', `${px * 100}%`);
      el.style.setProperty('--sy', `${py * 100}%`);
      el.style.transform = `perspective(900px) rotateX(${-y * 7}deg) rotateY(${x * 8}deg) translateY(-5px) translateZ(8px)`;
    });
    el.addEventListener('pointerleave', () => {
      el.style.transform = '';
    });
  }

  function bindTilt() {
    document.querySelectorAll('.login-card, .dashboard-card, .panel').forEach(enableTilt);
  }

  function bindHeroParallax() {
    const hero = document.querySelector('.hero');
    const loginPage = document.querySelector('.login-page');
    if (!hero || !loginPage || !finePointer || reduced || hero.dataset.parallaxReady) return;
    hero.dataset.parallaxReady = '1';
    loginPage.addEventListener('pointermove', (e) => {
      const x = e.clientX / innerWidth - .5;
      const y = e.clientY / innerHeight - .5;
      hero.style.transform = `perspective(1000px) rotateX(${-y * 3}deg) rotateY(${x * 4}deg) translate3d(${x * 12}px,${y * 8}px,16px)`;
      const layers = hero.querySelectorAll('.eyebrow,h2,>p,.trust-row');
      layers.forEach((layer, i) => layer.style.transform = `translateZ(${14 + i * 8}px)`);
    });
    loginPage.addEventListener('pointerleave', () => hero.style.transform = '');
  }

  function bindMagnetic() {
    if (!finePointer || reduced) return;
    document.querySelectorAll('.signin,.google,.scan-row button,.demo button,.notification,.nav-button').forEach((el) => {
      if (el.dataset.magneticReady) return;
      el.dataset.magneticReady = '1';
      el.classList.add('magnetic');
      el.addEventListener('pointermove', (e) => {
        const r = el.getBoundingClientRect();
        const x = e.clientX - (r.left + r.width / 2);
        const y = e.clientY - (r.top + r.height / 2);
        el.style.transform = `translate(${x * .08}px,${y * .12}px)`;
        if (ring) ring.classList.add('is-hot');
      });
      el.addEventListener('pointerleave', () => {
        el.style.transform = '';
        if (ring) ring.classList.remove('is-hot');
      });
    });
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: .1 });

  function bindReveal() {
    document.querySelectorAll('.dashboard-card, .panel, .feature').forEach((el, i) => {
      if (el.dataset.revealReady) return;
      el.dataset.revealReady = '1';
      el.classList.add('reveal-item');
      el.style.transitionDelay = `${Math.min(i % 4, 3) * 75}ms`;
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

  function addDepthFloat() {
    document.querySelectorAll('.dashboard-card,.panel-symbol,.mini-mark,.shield').forEach((el) => el.classList.add('depth-float'));
  }

  function refreshInteractiveUI() {
    bindTilt();
    bindHeroParallax();
    bindMagnetic();
    bindReveal();
    bindRipples();
    bindNavState();
    addDepthFloat();
  }

  document.addEventListener('DOMContentLoaded', refreshInteractiveUI);
  const mutationObserver = new MutationObserver(() => refreshInteractiveUI());
  mutationObserver.observe(document.documentElement, { childList: true, subtree: true });
})();