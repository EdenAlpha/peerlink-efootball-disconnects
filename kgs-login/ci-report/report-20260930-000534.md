## capture

### step 01 (binder + android)
```text
+ id
uid=1001(runner) gid=1001(runner) groups=1001(runner),4(adm),100(users),118(docker),999(systemd-journal)
++ whoami
++ '[' -w /root ']'
++ echo no
+ echo 'whoami=runner  writable /root? no'
whoami=runner  writable /root? no
+ sudo apt-get update -qq
+ tail -2
++ uname -r
+ sudo apt-get install -y -qq kmod linux-modules-extra-6.17.0-1022-azure

No VM guests are running outdated hypervisor (qemu) binaries on this host.
++ uname -r
+ find /lib/modules/6.17.0-1022-azure -name 'binder*'
/lib/modules/6.17.0-1022-azure/kernel/drivers/android/binder_linux.ko.zst
+ sudo modprobe binder_linux devices=binder,hwbinder,vndbinder
+ sudo modprobe binder_linux
+ lsmod
+ grep -i binder
binder_linux          221184  0
+ sudo mkdir -p /dev/binderfs
+ sudo mount -t binder binder /dev/binderfs
+ mount
+ grep -qi binder
+ mount
+ grep -i binder
binder on /dev/binderfs type binder (rw,relatime,max=1048576)
+ sudo mkdir -p /root/rd
+ sudo docker rm -f redroid
+ sudo docker run -d --name redroid --privileged -v /root/rd:/data -p 5555:5555 -p 27042:27042 redroid/redroid:14.0.0_64only-latest androidboot.redroid_width=720 androidboot.redroid_height=1280 androidboot.redroid_dpi=320 androidboot.use_memfd=true
Unable to find image 'redroid/redroid:14.0.0_64only-latest' locally
14.0.0_64only-latest: Pulling from redroid/redroid
bbb77fa6888e: Pulling fs layer
bbb77fa6888e: Verifying Checksum
bbb77fa6888e: Download complete
bbb77fa6888e: Pull complete
Digest: sha256:0a611199ba2e0b5d60af39b3327a517f6407231f4352114ed3bd3cbfe2be69aa
Status: Downloaded newer image for redroid/redroid:14.0.0_64only-latest
8bfadb77703fc2a15f76c5af052112f7b58c81db2ba736b3b532386b9ea2269b
+ booted=0
++ seq 1 36
+ for i in $(seq 1 36)
++ sudo docker exec redroid getprop sys.boot_completed
++ tr -d '\r'
+ '[' '' = 1 ']'
+ sleep 5
+ for i in $(seq 1 36)
++ sudo docker exec redroid getprop sys.boot_completed
++ tr -d '\r'
+ '[' '' = 1 ']'
+ sleep 5
+ for i in $(seq 1 36)
++ sudo docker exec redroid getprop sys.boot_completed
++ tr -d '\r'
+ '[' 1 = 1 ']'
+ echo 'BOOTED after 15s'
BOOTED after 15s
+ booted=1
+ break
+ '[' 1 '!=' 1 ']'
+ sudo docker exec redroid id
uid=0(root) gid=0(root) groups=0(root)
+ sudo docker exec redroid getprop ro.odm.product.cpu.abilist64
arm64-v8a
+ echo '--- graphics capability inside android ---'
--- graphics capability inside android ---
+ sudo docker exec redroid sh -c 'ls /vendor/lib64/hw/ 2>/dev/null | head -20'
android.hardware.audio.effect@7.0-impl.so
android.hardware.audio@7.0-impl.so
android.hardware.graphics.allocator@2.0-impl.so
android.hardware.graphics.mapper@2.0-impl-2.1.so
audio.primary.default.so
audio.r_submix.default.so
gralloc.cros.so
gralloc.default.so
gralloc.gbm.so
gralloc.redroid.so
hwcomposer.redroid.so
local_time.default.so
power.default.so
vibrator.default.so
vulkan.broadcom.so
vulkan.freedreno.so
vulkan.lvp.so
vulkan.nouveau.so
vulkan.panfrost.so
vulkan.pastel.so
+ sudo docker exec redroid sh -c 'ls /system/lib64/libEGL.so /system/lib64/libGLESv3.so /system/lib64/libvulkan.so 2>&1'
/system/lib64/libEGL.so
/system/lib64/libGLESv3.so
/system/lib64/libvulkan.so
+ sudo docker exec redroid sh -c 'ls /vendor/lib64/libvulkan.so /vendor/lib64/hw/vulkan.*.so 2>&1'
ls: /vendor/lib64/libvulkan.so: No such file or directory
/vendor/lib64/hw/vulkan.broadcom.so
/vendor/lib64/hw/vulkan.freedreno.so
/vendor/lib64/hw/vulkan.lvp.so
/vendor/lib64/hw/vulkan.nouveau.so
/vendor/lib64/hw/vulkan.panfrost.so
/vendor/lib64/hw/vulkan.pastel.so
```

### pipeline (apkeep, frida, install, capture)
```text
+ '[' 862294575 -gt 100000000 ']'
+ cd /tmp/kgs
+ XAPK=/tmp/kgs/jp.konami.pesam.xapk
+ python3 -
version 11.0.1 311000101
22 splits in the bundle
  jp.konami.pesam.apk            -> base.apk                             22.3 MB
  config.de.apk                  -> split_config.de.apk                   0.0 MB
  config.fr.apk                  -> split_config.fr.apk                   0.0 MB
  config.my.apk                  -> split_config.my.apk                   0.0 MB
  pad_it_0.apk                   -> split_pad_it_0.apk                  386.4 MB
  pad_it_1.apk                   -> split_pad_it_1.apk                  395.4 MB
  config.hi.apk                  -> split_config.hi.apk                   0.0 MB
  config.th.apk                  -> split_config.th.apk                   0.0 MB
  config.tr.apk                  -> split_config.tr.apk                   0.0 MB
  config.vi.apk                  -> split_config.vi.apk                   0.0 MB
  config.ar.apk                  -> split_config.ar.apk                   0.0 MB
  config.en.apk                  -> split_config.en.apk                   0.0 MB
  config.in.apk                  -> split_config.in.apk                   0.0 MB
  config.ja.apk                  -> split_config.ja.apk                   0.0 MB
  config.ru.apk                  -> split_config.ru.apk                   0.0 MB
  config.arm64_v8a.apk           -> split_config.arm64_v8a.apk           57.1 MB
  config.es.apk                  -> split_config.es.apk                   0.0 MB
  config.it.apk                  -> split_config.it.apk                   0.0 MB
  config.ko.apk                  -> split_config.ko.apk                   0.0 MB
  config.pt.apk                  -> split_config.pt.apk                   0.0 MB
  config.xxxhdpi.apk             -> split_config.xxxhdpi.apk              0.2 MB
  config.zh.apk                  -> split_config.zh.apk                   0.0 MB
+ '[' -f /tmp/kgs/out/.ok ']'
+ echo '--- copying into the container ---'
--- copying into the container ---
+ sudo docker exec redroid mkdir -p /data/local/tmp/splits
+ sudo docker cp /tmp/kgs/out/. redroid:/data/local/tmp/splits/
+ sudo docker exec redroid sh -c 'ls /data/local/tmp/splits/*.apk | wc -l'
22
+ sudo docker exec redroid sh -c 'ls -la /data/local/tmp/splits/*.apk'
+ head -30
-rw-r--r-- 1 radio radio  22347497 2026-09-30 00:05 /data/local/tmp/splits/base.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 /data/local/tmp/splits/split_config.ar.apk
-rw-r--r-- 1 radio radio  57148181 2026-09-30 00:05 /data/local/tmp/splits/split_config.arm64_v8a.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 /data/local/tmp/splits/split_config.de.apk
-rw-r--r-- 1 radio radio     37074 2026-09-30 00:05 /data/local/tmp/splits/split_config.en.apk
-rw-r--r-- 1 radio radio     24786 2026-09-30 00:05 /data/local/tmp/splits/split_config.es.apk
-rw-r--r-- 1 radio radio     24786 2026-09-30 00:05 /data/local/tmp/splits/split_config.fr.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 /data/local/tmp/splits/split_config.hi.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 /data/local/tmp/splits/split_config.in.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 /data/local/tmp/splits/split_config.it.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 /data/local/tmp/splits/split_config.ja.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 /data/local/tmp/splits/split_config.ko.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 /data/local/tmp/splits/split_config.my.apk
-rw-r--r-- 1 radio radio     24786 2026-09-30 00:05 /data/local/tmp/splits/split_config.pt.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 /data/local/tmp/splits/split_config.ru.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 /data/local/tmp/splits/split_config.th.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 /data/local/tmp/splits/split_config.tr.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 /data/local/tmp/splits/split_config.vi.apk
-rw-r--r-- 1 radio radio    198371 2026-09-30 00:05 /data/local/tmp/splits/split_config.xxxhdpi.apk
-rw-r--r-- 1 radio radio     28882 2026-09-30 00:05 /data/local/tmp/splits/split_config.zh.apk
-rw-r--r-- 1 radio radio 386375435 2026-09-30 00:05 /data/local/tmp/splits/split_pad_it_0.apk
-rw-r--r-- 1 radio radio 395420368 2026-09-30 00:05 /data/local/tmp/splits/split_pad_it_1.apk
+ echo '--- what pm actually offers (for the record) ---'
--- what pm actually offers (for the record) ---
+ sudo docker exec redroid sh -c 'pm help 2>&1 | head -20'
Package manager (package) commands:
  help
    Print this help text.

  path [--user USER_ID] PACKAGE
    Print the path to the .apk of the given PACKAGE.

  dump PACKAGE
    Print various system state associated with the given PACKAGE.

  has-feature FEATURE_NAME [version]
    Prints true and returns exit status 0 when system has a FEATURE_NAME,
    otherwise prints false and returns exit status 1

  list features
    Prints all features of the system.

  list instrumentation [-f] [TARGET-PACKAGE]
    Prints all test packages; optionally only those targeting TARGET-PACKAGE
    Options:
+ echo '--- install adb on the host ---'
--- install adb on the host ---
+ sudo apt-get install -y -qq adb
+ tail -2

No VM guests are running outdated hypervisor (qemu) binaries on this host.
+ which adb
/usr/bin/adb
+ adb version
+ head -2
Android Debug Bridge version 1.0.41
Version 34.0.4-debian
+ echo '--- connect to redroid ---'
--- connect to redroid ---
+ adb connect 127.0.0.1:5555
+ tail -2
* daemon started successfully
connected to 127.0.0.1:5555
+ adb wait-for-device
error: more than one device/emulator
+ adb shell getprop sys.boot_completed
adb: more than one device/emulator
+ echo '--- push the splits ---'
--- push the splits ---
+ adb shell mkdir -p /data/local/tmp/splits
adb: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/base.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.ar.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.arm64_v8a.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.de.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.en.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.es.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.fr.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.hi.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.in.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.it.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.ja.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.ko.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.my.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.pt.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.ru.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.th.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.tr.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.vi.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ tail -1
+ adb push /tmp/kgs/out/split_config.xxxhdpi.apk /data/local/tmp/splits/
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_config.zh.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_pad_it_0.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ for f in $W/out/*.apk
+ adb push /tmp/kgs/out/split_pad_it_1.apk /data/local/tmp/splits/
+ tail -1
adb: error: failed to get feature set: more than one device/emulator
+ adb shell ls -la /data/local/tmp/splits/
+ head -30
adb: more than one device/emulator
+ echo '--- adb install-multiple (base first, then the rest) ---'
--- adb install-multiple (base first, then the rest) ---
+ ok=0
+ adb install-multiple -r -g /data/local/tmp/splits/base.apk /data/local/tmp/splits/split_config.arm64_v8a.apk
+ tail -8
adb: more than one device/emulator
+ ok=1
+ '[' 1 '!=' 1 ']'
+ '[' 1 '!=' 1 ']'
+ echo '--- verify ---'
--- verify ---
+ adb shell pm list packages
+ grep -i konami
+ true
+ grep -i konami
+ sudo docker exec redroid /system/bin/pm list packages
+ true
+ echo '--- package state ---'
--- package state ---
+ sudo docker exec redroid /system/bin/pm list packages
+ grep -i konami
+ echo '=== GAME NOT INSTALLED AT ALL ==='
=== GAME NOT INSTALLED AT ALL ===
+ sudo docker exec redroid sh -c 'ls -la /data/local/tmp/splits/'
total 841772
drwxr-xr-x 2 root  root       4096 2026-09-30 00:05 .
drwxrwx--x 4 shell shell      4096 2026-09-30 00:05 ..
-rw-r--r-- 1 radio radio         2 2026-09-30 00:05 .ok
-rw-r--r-- 1 radio radio  22347497 2026-09-30 00:05 base.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 split_config.ar.apk
-rw-r--r-- 1 radio radio  57148181 2026-09-30 00:05 split_config.arm64_v8a.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 split_config.de.apk
-rw-r--r-- 1 radio radio     37074 2026-09-30 00:05 split_config.en.apk
-rw-r--r-- 1 radio radio     24786 2026-09-30 00:05 split_config.es.apk
-rw-r--r-- 1 radio radio     24786 2026-09-30 00:05 split_config.fr.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 split_config.hi.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 split_config.in.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 split_config.it.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 split_config.ja.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 split_config.ko.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 split_config.my.apk
-rw-r--r-- 1 radio radio     24786 2026-09-30 00:05 split_config.pt.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 split_config.ru.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 split_config.th.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 split_config.tr.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:05 split_config.vi.apk
-rw-r--r-- 1 radio radio    198371 2026-09-30 00:05 split_config.xxxhdpi.apk
-rw-r--r-- 1 radio radio     28882 2026-09-30 00:05 split_config.zh.apk
-rw-r--r-- 1 radio radio 386375435 2026-09-30 00:05 split_pad_it_0.apk
-rw-r--r-- 1 radio radio 395420368 2026-09-30 00:05 split_pad_it_1.apk
+ exit 1
```

### frida
```text
```

### logcat (filtered)
```text
```
