import os, subprocess, shutil, xml.etree.ElementTree as ET
import lief

if os.path.exists('./tmp-building'):
    print("Cleaning up from previous run...")
    shutil.rmtree('./tmp-building')

print("Extracting original APK...")
subprocess.run(['java', '-jar', './executables/apktool.jar', 'd', '-f', '-s', '-o', './tmp-building', './original.apk']) # Extract original APK
shutil.copyfile('./resources/libfrida-gadget.so', './tmp-building/lib/arm64-v8a/libfrida-gadget.so') # Copy frida gadget

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
libnative.write("./tmp-tmp-buildinging/lib/arm64-v8a/libmain.so")

# Build APKs
print("Building server dependent APK...")
subprocess.run(['java', '-jar', './executables/apktool.jar', 'b', './tmp-building', '-d', '-o', './serverDependent.apk']) # Frida relies on connected device with frida-server running
print("Building local script dependent APK...")
shutil.copyfile('./libfrida-gadget.config.json', './tmp-building/assets/libfrida-gadget.config.so') # Copy frida gadget config
subprocess.run(['java', '-jar', './executables/apktool.jar', 'b', './tmp-building', '-d', '-o', './localScript.apk']) # Frida runs script from local file system

# Sign APKs
print("Signing APKs...")
subprocess.run(['java', '-jar', './executables/uber-apk-signer.jar', '--overwrite', '--apks', './localScript.apk', './serverDependent.apk'])

# Cleanup
print("Cleaning up...")
shutil.rmtree('./tmp-building')

print("Done!")