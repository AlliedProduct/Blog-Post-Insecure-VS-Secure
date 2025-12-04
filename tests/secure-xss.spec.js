const { test, expect } = require('@playwright/test');

  async function login(page, baseUrl) {
    await page.goto(`${baseUrl}/login`);
    await page.fill('input[name="username"]', 'test');   // your username
    await page.fill('input[name="password"]', 'test');   // your password
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(new RegExp(`${baseUrl.replace(/\//g, '\\/')}/dashboard`));
  }

  test('secure: reflected XSS on /search does NOT execute', async ({ page }) => {
    const baseUrl = 'http://localhost:3001';

    await login(page, baseUrl);

    let dialogSeen = false;
    page.on('dialog', async dialog => {
      dialogSeen = true;
      await dialog.dismiss();
    });

    const payload = '<script>alert("XSS")</script>';
    const encoded = encodeURIComponent(payload);

    await page.goto(`${baseUrl}/search?q=${encoded}`);

    await page.waitForTimeout(1000);

    // no alert
    expect(dialogSeen).toBeFalsy();

    // payload should appear as text
    const inputVal = await page.inputValue('input[name="q"]');
    expect(inputVal).toBe(payload);
  });

  test('secure: DOM XSS via welcome parameter does NOT execute', async ({ page }) => {
    const baseUrl = 'http://localhost:3001';

    // Use your test/test login
    await login(page, baseUrl);

    let dialogSeen = false;
    page.on('dialog', async dialog => {
      dialogSeen = true;
      await dialog.dismiss();
    });

    const payload = '<img src=x onerror="alert(\\"DOM XSS\\")">';
    const encoded = encodeURIComponent(payload);

    // In the secure version, dashboard uses textContent for the welcome message
    await page.goto(`${baseUrl}/dashboard?welcome=${encoded}`);

    await page.waitForTimeout(1000);

    // 1) No alert should have fired
    expect(dialogSeen).toBeFalsy();

    // 2) Payload should appear as harmless text in the page
    const bodyText = await page.textContent('body');
    expect(bodyText).toContain(payload);
  });