# frida-apk-injector
Injects frida-gadget and proxy support into whatever apk you'd like, includes apk download script which downloads from google playstore.

# Usage
## `build-apks.py`
Injects frida-gadget into `original.apk`, outputs `scriptDependent.apk` and `serverDependent.apk`.\
`scriptDependent.apk` includes `libfrida-gadget.config.json` and can run independently.\
`serverDependent.apk` requires frida-server to be running.
## `download-apk.py`
Downloads apk from google playstore by using playwright to scrape apkcombo.\
Change the PACKAGE_NAME variable before running.

# Folders
Binaries used to sign, unpack, repack, etc are stored at `binaries/`.\
Resources such as `libfrida-gadget.so` are stored at `resources/`.\
Unpacked apk will be temporarily stored at `tmp-building/` until build is finished.
