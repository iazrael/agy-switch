import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('every app command has an explicit window capability', () => {
  const invoke = read('src-tauri/src/lib.rs').split('.invoke_handler(tauri::generate_handler![')[1].split('])')[0];
  const registered = [...invoke.matchAll(/::(\w+),/g)].map(([, name]) => name);
  const build = read('src-tauri/build.rs').split('const COMMANDS: &[&str] = &[')[1].split('];')[0];
  const registeredInManifest = [...build.matchAll(/"(\w+)"/g)].map(([, name]) => name);
  const main = JSON.parse(read('src-tauri/capabilities/default.json'));
  const grants = registered.map(name => `allow-${name.replaceAll('_', '-')}`);

  assert.deepEqual(registeredInManifest.sort(), [...registered].sort());
  assert.deepEqual(main.windows, ['main']);
  assert.deepEqual(main.permissions.filter(name => name.startsWith('allow-')).sort(), grants.sort());
  assert.ok(!registered.includes('export_accounts'));
});

test('quick dashboard is limited to the commands needed for tray interactions', () => {
  const tray = JSON.parse(read('src-tauri/capabilities/menubar.json'));
  assert.deepEqual(tray.windows, ['menubar']);
  assert.deepEqual(tray.permissions.filter(name => name.startsWith('allow-')).sort(), [
    'allow-get-menu-bar-appearance', 'allow-get-menu-bar-snapshot', 'allow-get-menu-bar-usage',
    'allow-hide-menu-bar-dashboard', 'allow-open-app-page', 'allow-open-project-page',
    'allow-quit-app', 'allow-refresh-all-quotas', 'allow-switch-account',
  ]);
});

test('the startup theme is compatible with a policy that restricts inline scripts', () => {
  const { app } = JSON.parse(read('src-tauri/tauri.conf.json'));
  const scripts = app.security.csp.split(';').map(rule => rule.trim()).find(rule => rule.startsWith('script-src '));
  assert.equal(scripts, "script-src 'self'");
  assert.ok(!/<script\s*>/i.test(read('index.html')));
  assert.match(read('index.html'), /<script src="\/boot-theme\.js"><\/script>/);
});
