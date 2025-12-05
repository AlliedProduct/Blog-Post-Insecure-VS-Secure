const { test, expect } = require('@playwright/test');
  async function login(page, baseUrl, username, password) {
    await page.goto(`${baseUrl}/login`);
    await page.fill('input[name="username"]', username);
    await page.fill('input[name="password"]', password);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(new RegExp(`${baseUrl.replace(/\//g, '\\/')}/dashboard`));
  }

  test('secure: session cookie is NOT visible to JavaScript', async ({ page }) => {
    const baseUrl = 'http://localhost:3001';

    await login(page, baseUrl, 'test', 'test');

    // HttpOnly prevents js from reading the cookie
    const cookieString = await page.evaluate(() => document.cookie);

    expect(cookieString).not.toContain('connect.sid');
  });

  test('secure: stored XSS does NOT execute and is shown as text', async ({ page }) => {
    const baseUrl = 'http://localhost:3001';

    await login(page, baseUrl, 'test', 'test');

    let dialogSeen = false;
    page.on('dialog', async dialog => {
      dialogSeen = true;
      await dialog.dismiss();
    });

    await page.goto(`${baseUrl}/posts/create`);

    // posting malicious payload 
    await page.fill(
      'textarea[name="content"]',
      '<script>alert(document.cookie)</script>'
    );
    await page.click('button[type="submit"]');

    await page.goto(`${baseUrl}/dashboard`);
    await page.waitForTimeout(1000);

    expect(dialogSeen).toBeFalsy();
    // check for payload
    const bodyText = await page.textContent('body');
    expect(bodyText).toContain('<script>alert(document.cookie)</script>');

  });