// Drives the real dashboard in headless Chromium: a refused login, a login with a TOTP
// code, the overview, devices (with the filter), incidents, an approval with a fresh code
// if one is waiting, and the skip link. Fails on any console error, including a CSP
// violation. Use a test account on the dev database, never a real one:
//
//   just serve --dev          (in another terminal)
//   GNOMEHOME_USER=owner GNOMEHOME_PASSWORD=... GNOMEHOME_TOTP_SECRET=... just web-e2e
//
// Needs Node and Playwright (npm install -g playwright, then npx playwright install chromium).
const { chromium } = require('playwright');
const crypto = require('crypto');
const fs = require('fs');
const url = process.env.GNOMEHOME_URL || 'http://127.0.0.1:8787/';
const user = process.env.GNOMEHOME_USER;
const password = process.env.GNOMEHOME_PASSWORD;
const secret = process.env.GNOMEHOME_TOTP_SECRET;
const dir = process.env.GNOMEHOME_SHOTS || 'data/screenshots';
if (!user || !password || !secret) {
  console.error('Set GNOMEHOME_USER, GNOMEHOME_PASSWORD, and GNOMEHOME_TOTP_SECRET.');
  process.exit(2);
}
fs.mkdirSync(dir, { recursive: true });

function base32(s) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, value = 0; const out = [];
  for (const c of s) { value = (value << 5) | alphabet.indexOf(c); bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(out);
}
function totp(step) {
  const msg = Buffer.alloc(8); msg.writeBigInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', base32(secret)).update(msg).digest();
  const o = h[19] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1000000)).padStart(6, '0');
}
const step = () => Math.floor(Date.now() / 1000 / 30);

(async () => {
  const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  const errors = [];
  // The pre-login session check and the deliberately wrong code answer 401: expected.
  page.on('console', m => { if (m.type() === 'error' && !m.text().includes('status of 401')) errors.push(m.text()); });
  page.on('pageerror', e => errors.push(String(e)));

  await page.goto(url);
  await page.getByLabel('Username').waitFor();
  await page.screenshot({ path: `${dir}/1-login.png` });

  // A wrong code is refused with a generic message.
  await page.getByLabel('Username').fill(user);
  await page.getByLabel('Password').fill(password);
  await page.getByLabel('Code from your authenticator app').fill('000000');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByText('wrong username, password, or code').waitFor();
  console.log('wrong code refused: ok');

  const loginStep = step();
  await page.getByLabel('Password').fill(password);
  await page.getByLabel('Code from your authenticator app').fill(totp(loginStep));
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('heading', { name: 'Overview' }).waitFor();
  await page.waitForTimeout(1500);
  console.log('status line:', await page.locator('header.top .muted').innerText());
  await page.screenshot({ path: `${dir}/2-overview.png`, fullPage: true });

  await page.getByRole('button', { name: 'Devices' }).click();
  await page.getByRole('heading', { name: 'Devices' }).waitFor();
  const rows = await page.locator('tbody tr').count();
  console.log('device rows:', rows);
  await page.getByLabel('Filter by address, maker, name, or type').fill('camera');
  console.log('filtered rows:', await page.locator('tbody tr').count());
  await page.getByLabel('Filter by address, maker, name, or type').fill('');
  await page.screenshot({ path: `${dir}/3-devices.png`, fullPage: true });

  await page.getByRole('button', { name: 'Incidents' }).click();
  await page.getByRole('heading', { name: 'Incidents' }).waitFor();
  console.log('incident cards:', await page.locator('article.incident').count());
  await page.screenshot({ path: `${dir}/4-incidents.png`, fullPage: true });

  await page.getByRole('button', { name: 'Approvals' }).click();
  await page.getByRole('heading', { name: 'Approvals' }).waitFor();
  const waiting = await page.locator('article.incident').count();
  console.log('approvals waiting:', waiting);
  await page.screenshot({ path: `${dir}/5-approvals.png`, fullPage: true });
  if (waiting > 0) {
    // A code can't be reused, so wait for the next 30-second step.
    while (step() <= loginStep) await page.waitForTimeout(1000);
    const card = page.locator('article.incident').first();
    await card.getByLabel('Code').fill(totp(step()));
    await card.getByRole('button', { name: 'Approve' }).click();
    await page.getByText('Approved. GnomeHome will act within a minute.').waitFor();
    console.log('approval recorded: ok');
  }
  // Keyboard: on a fresh page, the first Tab reaches the skip link.
  await page.reload();
  await page.getByRole('heading', { name: 'Overview' }).waitFor();
  await page.keyboard.press('Tab');
  console.log('first tab stop:', await page.evaluate(() => document.activeElement.textContent));
  console.log('console errors:', errors.length ? errors : 'none');
  await browser.close();
  if (errors.length) process.exit(1);
})();
