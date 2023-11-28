import asyncio
from playwright.async_api import async_playwright
from playwright_stealth import stealth_async

PACKAGE_NAME = "com.foo.bar"

async def main():
    async with async_playwright() as p:
        browser = await p.firefox.launch()
        page = await browser.new_page()
        await stealth_async(page)
        await page.goto(f'https://apkcombo.com/_/{PACKAGE_NAME}/download/apk')
        download_btn = await page.wait_for_selector('#best-variant-tab > div:nth-child(1) > ul > li > ul > li > a')
        
        async with page.expect_download() as download_info:
            await download_btn.click()
        download = await download_info.value
        await download.save_as('./original.apk')
        await browser.close()

asyncio.run(main())
