(function () {
  try {
    const isMenubar = window.location.pathname.includes('menubar') ||
                      window.location.hash.includes('menubar') ||
                      window.location.search.includes('menubar') ||
                      window.location.href.includes('menubar');
    const savedTheme = localStorage.getItem('app-theme-preference');
    const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const shouldBeDark = savedTheme === 'dark' || ((!savedTheme || savedTheme === 'system') && systemDark);

    if (isMenubar) {
      document.documentElement.classList.add('panel-window');
      document.documentElement.style.setProperty('background-color', 'transparent', 'important');
      document.documentElement.style.setProperty('background', 'transparent', 'important');
    } else {
      document.documentElement.style.backgroundColor = shouldBeDark ? '#1a1f2e' : '#FAFBFC';
    }

    if (shouldBeDark) {
      document.documentElement.classList.add('dark');
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      document.documentElement.setAttribute('data-theme', 'light');
    }
  } catch (e) {
    console.error('Failed to apply theme during boot:', e);
  }
})();
