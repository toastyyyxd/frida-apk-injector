import os, subprocess, shutil, xml.etree.ElementTree as ET
import lief
from config_helper import open_config

CONFIG = open_config().build_config

def cleanup_tmp():
    print("Cleaning up...")
    shutil.rmtree('./tmp-building')

if os.path.exists('./tmp-building'):
    cleanup_tmp()

print("Extracting original APK...")
subprocess.run(['java', '-jar', './executables/apktool.jar', 'd', '-f', '-s', '-o', './tmp-building', './original.apk']) # Extract original APK
shutil.copyfile('./resources/libfrida-gadget.so', './tmp-building/lib/arm64-v8a/libfrida-gadget.so') # Copy frida gadget

if CONFIG.allow_proxy:
    print("Patching proxy support to AndroidManifest.xml...")
    shutil.copyfile('./resources/network_security_config.xml', './tmp-building/res/xml/network_security_config.xml') # Copy res/xml/network_security_config.xml
    # Add link to AndroidManifest.xml
    tree = ET.parse('./tmp-building/AndroidManifest.xml')
    root = tree.getroot()
    application = root.find("application")
    application.set("{http://schemas.android.com/apk/res/android}networkSecurityConfig", "@xml/network_security_config")
    tree.write('./tmp-building/AndroidManifest.xml')

# Inject frida gadget to libmain.so
print("Injecting Frida gadget to libmain.so...")
libnative = lief.parse("./tmp-building/lib/arm64-v8a/libmain.so")
libnative.add_library("libfrida-gadget.so") # Injection!
libnative.write("./tmp-building/lib/arm64-v8a/libmain.so") 

# Build APKs
print("Building server dependent APK...")
subprocess.run(['java', '-jar', './executables/apktool.jar', 'b', './tmp-building', '-d', '-o', './serverDependent.apk']) # Frida relies on connected device with frida-server running
print("Building local script dependent APK...")
shutil.copyfile('./libfrida-gadget.config.json', './tmp-building/assets/libfrida-gadget.config.so') # Copy frida gadget config
subprocess.run(['java', '-jar', './executables/apktool.jar', 'b', './tmp-building', '-d', '-o', './localScript.apk']) # Frida runs script from local file system

# Sign APKs
print("Signing APKs...")
sign_command = ['java', '-jar', './executables/uber-apk-signer.jar', '--overwrite', '--apks', './localScript.apk', './serverDependent.apk']
if CONFIG.keystore.path == "":
    if CONFIG.keystore.debug == False:
        print("No keystore path provided, embedded keystore is debug only")
        cleanup_tmp()
        exit()
else:
    sign_command.append(f'--ks{CONFIG.keystore.debug == True and "Debug" or ""}')
    sign_command.append(CONFIG.keystore.path)
    if CONFIG.keystore.debug == False:
        if CONFIG.keystore.password == "" or CONFIG.keystore.key_password == "" or CONFIG.keystore.alias == "":
            print("Missing ks_pass, ks_key_pass or ks_alias config parameters")
            cleanup_tmp()
            exit()
        sign_command.extend([
            '--ksAlias', CONFIG.keystore.alias,
            '--ksKeyPass', CONFIG.keystore.key_password,
            '--ksPass', CONFIG.keystore.password
        ])
subprocess.run(sign_command)

# Cleanup
cleanup_tmp()

print("Done!")