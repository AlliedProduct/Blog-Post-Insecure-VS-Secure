import { test, expect } from '@playwright/test';

test('insecure: stored XSS pops', async ({ page }) => {
  await page.goto('http://localhost:3000/login');
  await page.fill('input[name="username"]', 'testuser');
  await page.fill('input[name="password"]', 'password');
  await page.click('button[type="submit"]');

  await page.click('text=Create Post');
  await page.fill('textarea[name="content"]', '<script>alert("Stored XSS")</script>');
  await page.click('button[type="submit"]');

  // check that alert shows up
  page.on('dialog', async dialog => {
    expect(dialog.message()).toContain('Stored XSS');
    await dialog.accept();
  });

  await page.goto('http://localhost:3000/dashboard?force=1');
});

