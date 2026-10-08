[app]
title = OSINT
package.name = osint
package.domain = org.osint
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0
requirements = python3,kivy,requests,urllib3,chardet,idna,certifi
orientation = portrait
fullscreen = 0
android.permissions = INTERNET,ACCESS_NETWORK_STATE
android.api = 33
android.minapi = 21
android.ndk = 25b
p4a.branch = master

[buildozer]
log_level = 2
warn_on_root = 1
