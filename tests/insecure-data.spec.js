const { test, expect } = require('@playwright/test');

  async function login(page, baseUrl, username, password) {
    await page.goto(`${baseUrl}/login`);
    await page.fill('input[name="username"]', username);
    await page.fill('input[name="password"]', password);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(new RegExp(`${baseUrl.replace(/\//g, '\\/')}/dashboard`));
  }

    test('insecure: session cookie is visible via document.cookie', async ({ page }) => {
    const baseUrl = 'http://localhost:3000';

    await login(page, baseUrl, 'test', 'test');

    const cookieString = await page.evaluate(() => document.cookie);

    expect(cookieString).toContain('connect.sid');
  });

  test('insecure: stored XSS executes and exposes cookie', async ({ page }) => {
    const baseUrl = 'http://localhost:3000';

    await login(page, baseUrl, 'test', 'test');

    // listen for the first alert triggered
    let dialogMessage = null;
    page.once('dialog', async dialog => {
      dialogMessage = dialog.message();
      await dialog.dismiss();
    });

    // malicious post
    await page.goto(`${baseUrl}/posts/create`);
    await page.fill(
      'textarea[name="content"]',
      '<script>alert(document.cookie)</script>'
    );
    await page.click('button[type="submit"]');

    await page.waitForTimeout(1000);

    // check for alert message containing cookie
    expect(dialogMessage).not.toBeNull();
    expect(dialogMessage).toContain('connect.sid');
  });