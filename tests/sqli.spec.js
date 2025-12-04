const { test, expect } = require('@playwright/test');

  test('secure: SQL injection payload does NOT bypass login', async ({ page }) => {

    await page.goto('http://localhost:3001/login');

    const payload = "' OR '1'='1";

    await page.fill('input[name="username"]', payload);
    await page.fill('input[name="password"]', payload);
    await page.click('button[type="submit"]');

    await expect(page).toHaveURL(/\/login/);

    await expect(page.getByText('Invalid username or password')).toBeVisible();
  });