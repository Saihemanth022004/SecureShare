(function () {
  let authReady = null;

  let _cfgCache = null;
  async function getFirebaseConfig() {
    if (_cfgCache) return _cfgCache;
    localStorage.removeItem('firebase_config');
    const res = await fetch('/api/firebase-config');
    _cfgCache = await res.json();
    return _cfgCache;
  }

  async function initAuth() {
    if (authReady) return authReady;
    authReady = (async () => {
      const cfg = await getFirebaseConfig();
      if (!cfg.apiKey || !cfg.projectId) {
        throw new Error('Firebase web config missing on server');
      }

      if (!window.firebase.apps.length) {
        window.firebase.initializeApp(cfg);
      }

      const auth = window.firebase.auth();

      await new Promise((resolve) => {
        const unsub = auth.onAuthStateChanged(() => {
          unsub();
          resolve();
        });
      });

      auth.onIdTokenChanged(async (user) => {
        if (!user) {
          localStorage.removeItem('firebase_id_token');
          localStorage.removeItem('firebase_uid');
          return;
        }
        const token = await user.getIdToken();
        localStorage.setItem('firebase_id_token', token);
        localStorage.setItem('firebase_uid', user.uid);
      });
      return auth;
    })();
    return authReady;
  }

  function getToken() {
    return localStorage.getItem('firebase_id_token');
  }

  function isProtectedPath(pathname) {
    return pathname === '/upload' || pathname === '/dashboard' || pathname === '/result' || pathname === '/profile';
  }

  async function requireAuthForPage() {
    await initAuth();
    const auth = window.firebase.auth();
    if (!isProtectedPath(window.location.pathname)) return;
    if (auth.currentUser) return;
    window.location.href = '/login';
  }

  async function addAuthNav() {
    await initAuth();
    const nav = document.querySelector('.nav-links');
    if (!nav) return;

    const auth = window.firebase.auth();
    const user = auth.currentUser;
    const existing = document.getElementById('auth-nav-btn');
    if (existing) existing.remove();
    const existingProfile = document.getElementById('profile-nav-btn');
    if (existingProfile) existingProfile.remove();

    if (!user) {
      const existingLogin = nav.querySelector('a[href="/login"]');
      if (existingLogin) {
        existingLogin.classList.toggle('active', window.location.pathname === '/login');
        return;
      }
      const a = document.createElement('a');
      a.id = 'auth-nav-btn';
      a.href = '/login';
      a.className = window.location.pathname === '/login' ? 'active' : '';
      a.textContent = 'Login';
      nav.appendChild(a);
      return;
    }

    const btn = document.createElement('a');
    btn.id = 'auth-nav-btn';
    btn.href = '#';
    btn.textContent = 'Logout';
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      await auth.signOut();
      localStorage.removeItem('firebase_id_token');
      localStorage.removeItem('firebase_uid');
      window.location.href = '/login';
    });

    const hasProfileLink = !!nav.querySelector('a[href="/profile"]');
    if (!hasProfileLink) {
      const profile = document.createElement('a');
      profile.id = 'profile-nav-btn';
      profile.href = '/profile';
      profile.textContent = 'Profile';
      profile.className = window.location.pathname === '/profile' ? 'active' : '';
      nav.appendChild(profile);
    }

    nav.appendChild(btn);
  }

  window.AppAuth = {
    initAuth,
    getToken,
    requireAuthForPage,
    addAuthNav,
  };
})();
