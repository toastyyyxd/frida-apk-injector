import asyncio, questionary
from playwright.async_api import async_playwright, Page, Locator
from playwright_stealth import stealth_async
from config_helper import open_config, write_config

FULL_CONFIG = open_config()
CONFIG = FULL_CONFIG.download_config
if CONFIG.package_name == "":
    print("Missing config package name")
    exit()

"""
async def debug_stream(page: Page):
    while not page.is_closed():
        await page.screenshot(path="debug.png")
        with open('./debug.html', 'w') as f:
            f.write(await page.content())
        await asyncio.sleep(0.5)
""" # Only for debugging
        
async def wait_for_and_close_ad(page: Page):
    outer_iframes = await page.locator('iframe[id^="google_ads_iframe"]').all()
    coroutines = []
    for outer_iframe in outer_iframes:
        outer_iframe = outer_iframe.frame_locator(":scope")
        ad_iframe = outer_iframe.frame_locator('iframe#ad_iframe')
        close_btn = ad_iframe.locator('[aria-label="Close ad"]')
        coroutines.append(wait_for_ad_close_btn(close_btn))
    asyncio.gather(*coroutines)
async def wait_for_ad_close_btn(close_btn: Locator):
    try:
        await close_btn.wait_for()
        await close_btn.click(force=True, no_wait_after=True)
        print('Ad closed')
    except:
        0

async def main():
    async with async_playwright() as p:
        futures = []

        browser = await p.firefox.launch()
        page = await browser.new_page()
        await stealth_async(page)
        await page.goto(f'https://apkcombo.com/_/{CONFIG.package_name}/download/apk')
        #futures.append(asyncio.gather(debug_stream(page))) only for debugging

        version_name_span = page.locator('#best-variant-tab > div:nth-child(1) > ul > li > ul > li > a > div.info > div.header > span.vername').first
        await version_name_span.wait_for()
        version_name = (await version_name_span.text_content()).split(' ')[-1]

        version_code_span = page.locator('#best-variant-tab > div:nth-child(1) > ul > li > ul > li > a > div.info > div.header > span.vercode').first
        await version_code_span.wait_for()
        version_code = int((await version_code_span.text_content())[1:-1])

        print(f'Version Name: {version_name} \nVersion Code: {version_code}')

        if (version_name == CONFIG.last_version_name):
            answer = await questionary.confirm("The latest version name is identical to the last successful download, the downloaded APK might be duplicate, continue?").ask_async()
            if (not answer):
                exit()
        if (version_code == CONFIG.last_version_code):
            answer = await questionary.confirm("The latest version code is identical to the last successful download, the downloaded APK will be duplicate, continue?").ask_async()
            if (not answer):
                exit()
        if (version_code < CONFIG.last_version_code):
            answer = await questionary.confirm("The latest available version code is lower than the last successful download, but this shouldn't be possible, still continue?").ask_async()
            if (not answer):
                exit()
        
        download_btn = await page.wait_for_selector('#best-variant-tab > div:nth-child(1) > ul > li > ul > li > a')
        
        futures.append(asyncio.gather(wait_for_and_close_ad(page)))

        async with page.expect_download() as download_info:
            await download_btn.click()

        download = await download_info.value
        await download.save_as('./original.apk')
        
        CONFIG.last_version_code = version_code
        CONFIG.last_version_name = version_name
        write_config(FULL_CONFIG)

        await page.close()
        await asyncio.sleep(2)
        await browser.close()

        print("Done")

asyncio.run(main())
