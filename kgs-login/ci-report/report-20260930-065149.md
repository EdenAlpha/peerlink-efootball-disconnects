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
bbb77fa6888e: Download complete
bbb77fa6888e: Pull complete
Digest: sha256:0a611199ba2e0b5d60af39b3327a517f6407231f4352114ed3bd3cbfe2be69aa
Status: Downloaded newer image for redroid/redroid:14.0.0_64only-latest
481964cad1fcc44ebd1c4274cb070bea89a6af66fb2d3d143ea1a54dda3292d8
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
/vendor/lib64/hw/vulkan.radeon.so
```

### pipeline (apkeep, frida, install, capture)
```text
+ '[' -n 4860 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4860
++ grep -c '^### ' /tmp/kgs/flows.log
++ echo 0
+ echo '  phase4 t=320s gamepid=4860 flows=0
0'
  phase4 t=320s gamepid=4860 flows=0
0
+ sudo docker exec redroid /system/bin/input tap 915 405
+ sudo docker exec redroid /system/bin/input tap 500 435
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ sudo docker exec redroid sh -c 'screencap -p /data/local/tmp/screen_32.png'
+ '[' -n 4860 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4860
++ grep -c '^### ' /tmp/kgs/flows.log
++ echo 0
+ echo '  phase4 t=330s gamepid=4860 flows=0
0'
  phase4 t=330s gamepid=4860 flows=0
0
+ sudo docker exec redroid /system/bin/input tap 915 405
+ sudo docker exec redroid /system/bin/input tap 500 435
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ sudo docker exec redroid sh -c 'screencap -p /data/local/tmp/screen_33.png'
+ '[' -n 4860 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ tr -d '\r'
++ awk '{print $1}'
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
+ alive=4860
++ grep -c '^### ' /tmp/kgs/flows.log
++ echo 0
+ echo '  phase4 t=340s gamepid=4860 flows=0
0'
  phase4 t=340s gamepid=4860 flows=0
0
+ sudo docker exec redroid /system/bin/input tap 915 405
+ sudo docker exec redroid /system/bin/input tap 500 435
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ sudo docker exec redroid sh -c 'screencap -p /data/local/tmp/screen_34.png'
+ '[' -n 4860 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ awk '{print $1}'
++ tr -d '\r'
+ alive=4860
++ grep -c '^### ' /tmp/kgs/flows.log
++ echo 0
+ echo '  phase4 t=350s gamepid=4860 flows=0
0'
  phase4 t=350s gamepid=4860 flows=0
0
+ sudo docker exec redroid /system/bin/input tap 915 405
+ sudo docker exec redroid /system/bin/input tap 500 435
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ sudo docker exec redroid sh -c 'screencap -p /data/local/tmp/screen_35.png'
+ '[' -n 4860 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4860
++ grep -c '^### ' /tmp/kgs/flows.log
++ echo 0
+ echo '  phase4 t=360s gamepid=4860 flows=0
0'
  phase4 t=360s gamepid=4860 flows=0
0
+ sudo docker exec redroid /system/bin/input tap 915 405
+ sudo docker exec redroid /system/bin/input tap 500 435
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ sudo docker exec redroid sh -c 'screencap -p /data/local/tmp/screen_36.png'
+ '[' -n 4860 ']'
+ kill 22437
+ echo '--- diagnostic ladder: each layer proves the next ---'
--- diagnostic ladder: each layer proves the next ---
++ '[' 0 = 0 ']'
++ echo YES
+ echo 'CA trusted by phone: YES'
CA trusted by phone: YES
+ echo '1. SYNs at all (game2.pcap size / syn count):'
1. SYNs at all (game2.pcap size / syn count):
+ sudo docker exec redroid sh -c 'ls -la /data/local/tmp/game2.pcap 2>/dev/null; tcpdump -r /data/local/tmp/game2.pcap -c 2000 2>/dev/null | grep -c "S "'
-rw-r--r-- 1 root root 36864 2026-09-30 06:51 /data/local/tmp/game2.pcap
159
+ echo '2. proxy saw handshakes (mitm.log tail):'
2. proxy saw handshakes (mitm.log tail):
+ tail -15 /tmp/kgs/mitm.log
[06:45:03.177] Loading script kgs-login/scripts/mitm_addon.py
[06:45:03.179] Transparent Proxy listening at *:8080.
+ echo '3. destinations the game contacted:'
3. destinations the game contacted:
+ grep -h '^HOST-SEEN:' /tmp/kgs/flows.log
+ sort -u
+ head -20
+ echo '4. decrypted Konami requests/responses:'
4. decrypted Konami requests/responses:
+ grep -c '^### ' /tmp/kgs/flows.log
0
+ echo 0
0
+ grep '^### ' /tmp/kgs/flows.log
+ head -30
+ echo '--- pull the evidence ---'
--- pull the evidence ---
+ sudo docker cp redroid:/data/local/tmp/game2.pcap /tmp/kgs/game2.pcap
++ seq 1 36
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_1.png /tmp/kgs/screen_1.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_2.png /tmp/kgs/screen_2.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_3.png /tmp/kgs/screen_3.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_4.png /tmp/kgs/screen_4.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_5.png /tmp/kgs/screen_5.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_6.png /tmp/kgs/screen_6.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_7.png /tmp/kgs/screen_7.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_8.png /tmp/kgs/screen_8.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_9.png /tmp/kgs/screen_9.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_10.png /tmp/kgs/screen_10.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_11.png /tmp/kgs/screen_11.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_12.png /tmp/kgs/screen_12.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_13.png /tmp/kgs/screen_13.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_14.png /tmp/kgs/screen_14.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_15.png /tmp/kgs/screen_15.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_16.png /tmp/kgs/screen_16.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_17.png /tmp/kgs/screen_17.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_18.png /tmp/kgs/screen_18.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_19.png /tmp/kgs/screen_19.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_20.png /tmp/kgs/screen_20.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_21.png /tmp/kgs/screen_21.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_22.png /tmp/kgs/screen_22.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_23.png /tmp/kgs/screen_23.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_24.png /tmp/kgs/screen_24.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_25.png /tmp/kgs/screen_25.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_26.png /tmp/kgs/screen_26.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_27.png /tmp/kgs/screen_27.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_28.png /tmp/kgs/screen_28.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_29.png /tmp/kgs/screen_29.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_30.png /tmp/kgs/screen_30.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_31.png /tmp/kgs/screen_31.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_32.png /tmp/kgs/screen_32.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_33.png /tmp/kgs/screen_33.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_34.png /tmp/kgs/screen_34.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_35.png /tmp/kgs/screen_35.png
+ for i in $(seq 1 36)
+ sudo docker cp redroid:/data/local/tmp/screen_36.png /tmp/kgs/screen_36.png
+ head -8
+ ls -la /tmp/kgs/screen_1.png /tmp/kgs/screen_10.png /tmp/kgs/screen_11.png /tmp/kgs/screen_12.png /tmp/kgs/screen_13.png /tmp/kgs/screen_14.png /tmp/kgs/screen_15.png /tmp/kgs/screen_16.png /tmp/kgs/screen_17.png /tmp/kgs/screen_18.png /tmp/kgs/screen_19.png /tmp/kgs/screen_2.png /tmp/kgs/screen_20.png /tmp/kgs/screen_21.png /tmp/kgs/screen_22.png /tmp/kgs/screen_23.png /tmp/kgs/screen_24.png /tmp/kgs/screen_25.png /tmp/kgs/screen_26.png /tmp/kgs/screen_27.png /tmp/kgs/screen_28.png /tmp/kgs/screen_29.png /tmp/kgs/screen_3.png /tmp/kgs/screen_30.png /tmp/kgs/screen_31.png /tmp/kgs/screen_32.png /tmp/kgs/screen_33.png /tmp/kgs/screen_34.png /tmp/kgs/screen_35.png /tmp/kgs/screen_36.png /tmp/kgs/screen_4.png /tmp/kgs/screen_5.png /tmp/kgs/screen_6.png /tmp/kgs/screen_7.png /tmp/kgs/screen_8.png /tmp/kgs/screen_9.png
-rw-r--r-- 1 root root 786552 Sep 30 06:45 /tmp/kgs/screen_1.png
-rw-r--r-- 1 root root 532762 Sep 30 06:47 /tmp/kgs/screen_10.png
-rw-r--r-- 1 root root 532762 Sep 30 06:47 /tmp/kgs/screen_11.png
-rw-r--r-- 1 root root 532762 Sep 30 06:47 /tmp/kgs/screen_12.png
-rw-r--r-- 1 root root 532762 Sep 30 06:47 /tmp/kgs/screen_13.png
-rw-r--r-- 1 root root 532762 Sep 30 06:47 /tmp/kgs/screen_14.png
-rw-r--r-- 1 root root 532762 Sep 30 06:47 /tmp/kgs/screen_15.png
-rw-r--r-- 1 root root 532762 Sep 30 06:48 /tmp/kgs/screen_16.png
+ cp -f /tmp/kgs/flows.log /flows-decrypted.log
+ true
+ cp -f /tmp/kgs/mitm.log /mitm.log
+ true
+ '[' 0 '!=' 0 ']'
+ echo '--- memory scan retired; the intercept above is the capture ---'
--- memory scan retired; the intercept above is the capture ---
+ echo '--- decrypted flows (the actual result) ---'
--- decrypted flows (the actual result) ---
+ grep -c '^### ' /tmp/kgs/flows.log
0
+ echo 0
0
+ grep '^### ' /tmp/kgs/flows.log
+ head -40
+ echo '--- destinations contacted ---'
--- destinations contacted ---
+ grep -h '^HOST-SEEN:' /tmp/kgs/flows.log
+ sort -u
+ head -20
+ echo '--- proxy errors (pinning/trust failures show here) ---'
--- proxy errors (pinning/trust failures show here) ---
+ grep -iE 'error|warn|tls|handshake|certificate' /tmp/kgs/mitm.log
+ tail -20
+ sudo docker exec redroid logcat -d -t 400
+ echo '=== logcat phase 3 (filtered) ==='
=== logcat phase 3 (filtered) ===
+ grep -iE 'konami|pesam|FATAL|AndroidRuntime|libUE4|Vulkan|EGL' /tmp/kgs/logcat-p3.txt
+ tail -40
+ sudo docker exec redroid sh -c 'pkill -f tcpdump; ls -la /data/local/tmp/game.pcap'
+ true
+ sudo docker exec redroid sh -c 'cat /data/local/tmp/tcpdump.out 2>&1'
+ tail -5
tcpdump: data link type LINUX_SLL2
tcpdump: listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
0 packets captured
0 packets received by filter
0 packets dropped by kernel
+ sudo docker cp redroid:/data/local/tmp/game.pcap /tmp/kgs/game.pcap
+ ls -la /tmp/kgs/game.pcap
-rw-r--r-- 1 root root 24 Sep 30 06:38 /tmp/kgs/game.pcap
+ echo 'GAME PCAP CAPTURED: /tmp/kgs/game.pcap'
GAME PCAP CAPTURED: /tmp/kgs/game.pcap
```

### frida
```text
     ____
    / _  |   Frida 17.19.0 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   Prefer a GUI? Luma is the official Frida app, with a live REPL,
   . . . .   persistent sessions & collaboration. https://luma.frida.re/
   . . . .
   . . . .   Connected to 127.0.0.1:27042 (id=socket@127.0.0.1:27042)
Spawning `jp.konami.pesam`...
Failed to spawn: error receiving data: Connection reset by peer
```

### logcat (filtered)
```text
09-30 06:34:59.995  1164  1196 D MediaGrants: Removed 0 media_grants for 0 user for jp.konami.pesam. Reason: Mode changed: android:read_external_storage
09-30 06:34:59.996  1164  1196 D MediaGrants: Removed 0 media_grants for 0 user for jp.konami.pesam. Reason: Mode changed: android:read_external_storage
09-30 06:34:59.996  1164  1196 D MediaGrants: Removed 0 media_grants for 0 user for jp.konami.pesam. Reason: Mode changed: android:read_external_storage
09-30 06:35:00.015  2145  2147 W ziparchive: Unable to open '/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg==/base.dm': No such file or directory
09-30 06:35:00.015  2145  2147 W ziparchive: Unable to open '/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg==/base.dm': No such file or directory
09-30 06:35:00.018  2145  2147 I artd    : Running dex2oat: /apex/com.android.art/bin/art_exec --drop-capabilities --set-task-profile=Dex2OatBootComplete --set-priority=background --keep-fds=6:7:8:9:10 -- /apex/com.android.art/bin/dex2oat64 --zip-fd=6 --zip-location=/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg==/base.apk --oat-fd=7 --oat-location=/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg==/oat/arm64/base.odex --output-vdex-fd=8 --swap-fd=9 --class-loader-context-fds=10 --class-loader-context=PCL[]{PCL[/system/framework/org.apache.http.legacy.jar]} --classpath-dir=/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg== --instruction-set=arm64 --instruction-set-features=default --instruction-set-variant=generic --compiler-filter=verify --compilation-reason=install --compact-dex-level=none --max-image-block-size=524288 --resolve-startup-const-strings=true --generate-mini-debug-info --runtime-arg -Xdeny-art-apex-data-files --runtime-arg -Xtarget-sdk-version:36 --runtime-arg -Xhidden-api-policy:enabled --runtime-arg -Xms64m --runtime-arg -Xmx512m --comments=app-version-name:11.0.1,app-version-code:311000101,art-version:-1
09-30 06:35:00.018  2145  2147 I artd    : Opened FDs: 6:/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg==/base.apk 7:/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg==/oat/arm64/base.odex.7yz4dC.tmp 8:/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg==/oat/arm64/base.vdex.2zVmXs.tmp 9:/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg==/oat/arm64/base.odex.swap.D3phTm.tmp 10:/system/framework/org.apache.http.legacy.jar 
09-30 06:35:00.036  2148  2148 W dex2oat64: /apex/com.android.art/bin/dex2oat64 --zip-fd=6 --zip-location=/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg==/base.apk --oat-fd=7 --oat-location=/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg==/oat/arm64/base.odex --output-vdex-fd=8 --swap-fd=9 --class-loader-context-fds=10 --class-loader-context=PCL[]{PCL[/system/framework/org.apache.http.legacy.jar]} --classpath-dir=/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg== --instruction-set=arm64 --instruction-set-features=default --instruction-set-variant=generic --compiler-filter=verify --compilation-reason=install --compact-dex-level=none --max-image-block-size=524288 --resolve-startup-const-strings=true --generate-mini-debug-info --runtime-arg -Xdeny-art-apex-data-files --runtime-arg -Xtarget-sdk-version:36 --runtime-arg -Xhidden-api-policy:enabled --runtime-arg -Xms64m --runtime-arg -Xmx512m --comments=app-version-name:11.0.1,app-version-code:311000101,art-version:-1
09-30 06:35:00.036  2148  2148 I dex2oat64: /apex/com.android.art/bin/dex2oat64 --output-vdex-fd=8 --class-loader-context-fds=10 --class-loader-context=PCL[]{PCL[/system/framework/org.apache.http.legacy.jar]} --classpath-dir=/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg== --compiler-filter=verify --compilation-reason=install --compact-dex-level=none --max-image-block-size=524288 --resolve-startup-const-strings=true --generate-mini-debug-info --comments=app-version-name:11.0.1,app-version-code:311000101,art-version:-1
09-30 06:35:00.417   231   278 I ArtService: Dexopt result: [packageName = jp.konami.pesam] DexContainerFileDexoptResult{dexContainerFile=/data/app/~~NZqbZR83o2OWoij8GPwIsg==/jp.konami.pesam-2NiiRWmpPL3txTHz4x8Vfg==/base.apk, primaryAbi=true, abi=arm64-v8a, actualCompilerFilter=verify, status=PERFORMED, dex2oatWallTimeMillis=401, dex2oatCpuTimeMillis=1100, sizeBytes=682616, sizeBeforeBytes=0}
09-30 06:35:00.419   231   278 V BackupManagerService: [UserID:0] restoreAtInstall pkg=jp.konami.pesam token=1 restoreSet=0
09-30 06:35:00.427   231   569 I SdkSandboxManager: No SDKs used. Skipping SDK data reconcilation for CallingInfo{mUid=10087, mPackageName='jp.konami.pesam, mAppProcessToken='null'}
09-30 06:35:00.428   852   903 D SessionCommitReceiver: Removing PromiseIcon for package: jp.konami.pesam, install reason: 0, alreadyAddedPromiseIcon: false
09-30 06:35:00.430   231   231 V GameManagerService_GamePackageConfiguration: No android.game_mode_config meta-data found for package jp.konami.pesam
09-30 06:35:00.431   804   804 D CarrierSvcBindHelper: onPackageAdded: jp.konami.pesam
09-30 06:35:00.431   231   231 V GameManagerService: Package configuration not found for jp.konami.pesam
09-30 06:35:00.435   605   605 I SafetyLabelChangedBroadcastReceiver: received broadcast packageName: jp.konami.pesam, current user: UserHandle{0}, packageChangeEvent: NEW_INSTALL, intent user: UserHandle{0}
09-30 06:35:00.443   804   804 D CarrierSvcBindHelper: onPackageModified: jp.konami.pesam
09-30 06:35:18.942   231  1545 I ActivityManager: Force stopping jp.konami.pesam appid=10087 user=0: from pid 2256
09-30 06:35:18.946   804   804 D CarrierSvcBindHelper: onHandleForceStop: [jp.konami.pesam]
09-30 06:35:19.023  2259  2259 D AndroidRuntime: >>>>>> START com.android.internal.os.RuntimeInit uid 0 <<<<<<
09-30 06:38:22.372   231  1545 I ActivityManager: Force stopping jp.konami.pesam appid=10087 user=0: from pid 2919
09-30 06:38:22.374   804   804 D CarrierSvcBindHelper: onHandleForceStop: [jp.konami.pesam]
```
