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
1602f135009fbd56f78f23b5c0090e180657c275d10c481653e7e88a151098fb
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
0 gamepid=4567
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4567 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4567
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=250s passes=0
0 gamepid=4567'
  phase3 t=250s passes=0
0 gamepid=4567
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4567 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ awk '{print $1}'
++ tr -d '\r'
+ alive=4567
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=260s passes=0
0 gamepid=4567'
  phase3 t=260s passes=0
0 gamepid=4567
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4567 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ awk '{print $1}'
++ tr -d '\r'
+ alive=4567
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=270s passes=0
0 gamepid=4567'
  phase3 t=270s passes=0
0 gamepid=4567
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4567 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4567
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=280s passes=0
0 gamepid=4567'
  phase3 t=280s passes=0
0 gamepid=4567
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4567 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4567
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=290s passes=0
0 gamepid=4567'
  phase3 t=290s passes=0
0 gamepid=4567
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4567 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4567
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=300s passes=0
0 gamepid=4567'
  phase3 t=300s passes=0
0 gamepid=4567
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4567 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4567
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=310s passes=0
0 gamepid=4567'
  phase3 t=310s passes=0
0 gamepid=4567
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4567 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ awk '{print $1}'
++ tr -d '\r'
+ alive=4567
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=320s passes=0
0 gamepid=4567'
  phase3 t=320s passes=0
0 gamepid=4567
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4567 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4567
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=330s passes=0
0 gamepid=4567'
  phase3 t=330s passes=0
0 gamepid=4567
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4567 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4567
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=340s passes=0
0 gamepid=4567'
  phase3 t=340s passes=0
0 gamepid=4567
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4567 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4567
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=350s passes=0
0 gamepid=4567'
  phase3 t=350s passes=0
0 gamepid=4567
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4567 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4567
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=360s passes=0
0 gamepid=4567'
  phase3 t=360s passes=0
0 gamepid=4567
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4567 ']'
+ kill 22232
+ echo '--- what frida itself said (this is what diagnosed the last run) ---'
--- what frida itself said (this is what diagnosed the last run) ---
+ head -14 /tmp/kgs/scan.log
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
Attaching...
Failed to attach: error receiving data: Connection reset by peer
+ echo '--- scanner output ---'
--- scanner output ---
+ grep -E '^\[scan\]|path=' /tmp/kgs/scan.log
+ head -80
+ echo '--- pass count: 0 WITH a frida error above means the scanner never'
--- pass count: 0 WITH a frida error above means the scanner never
+ echo '    ran, which is NOT the same as the game building no request ---'
    ran, which is NOT the same as the game building no request ---
+ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
0
+ echo 0
0
+ tail -20 /tmp/kgs/scan.log
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
Attaching...
Failed to attach: error receiving data: Connection reset by peer
+ cp -f /tmp/kgs/scan.log /scan-paths.log
+ true
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
-rw-r--r-- 1 root root 24 Sep 30 01:53 /tmp/kgs/game.pcap
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
Failed to spawn: connection closed
```

### logcat (filtered)
```text
09-30 01:50:17.327  1168  1344 D MediaGrants: Removed 0 media_grants for 0 user for jp.konami.pesam. Reason: Mode changed: android:read_external_storage
09-30 01:50:17.327  1168  1344 D MediaGrants: Removed 0 media_grants for 0 user for jp.konami.pesam. Reason: Mode changed: android:read_external_storage
09-30 01:50:17.328  1168  1344 D MediaGrants: Removed 0 media_grants for 0 user for jp.konami.pesam. Reason: Mode changed: android:read_external_storage
09-30 01:50:17.346  2156  2157 W ziparchive: Unable to open '/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q==/base.dm': No such file or directory
09-30 01:50:17.346  2156  2157 W ziparchive: Unable to open '/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q==/base.dm': No such file or directory
09-30 01:50:17.349  2156  2157 I artd    : Running dex2oat: /apex/com.android.art/bin/art_exec --drop-capabilities --set-task-profile=Dex2OatBootComplete --set-priority=background --keep-fds=6:7:8:9:10 -- /apex/com.android.art/bin/dex2oat64 --zip-fd=6 --zip-location=/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q==/base.apk --oat-fd=7 --oat-location=/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q==/oat/arm64/base.odex --output-vdex-fd=8 --swap-fd=9 --class-loader-context-fds=10 --class-loader-context=PCL[]{PCL[/system/framework/org.apache.http.legacy.jar]} --classpath-dir=/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q== --instruction-set=arm64 --instruction-set-features=default --instruction-set-variant=generic --compiler-filter=verify --compilation-reason=install --compact-dex-level=none --max-image-block-size=524288 --resolve-startup-const-strings=true --generate-mini-debug-info --runtime-arg -Xdeny-art-apex-data-files --runtime-arg -Xtarget-sdk-version:36 --runtime-arg -Xhidden-api-policy:enabled --runtime-arg -Xms64m --runtime-arg -Xmx512m --comments=app-version-name:11.0.1,app-version-code:311000101,art-version:-1
09-30 01:50:17.349  2156  2157 I artd    : Opened FDs: 6:/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q==/base.apk 7:/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q==/oat/arm64/base.odex.DHYhIa.tmp 8:/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q==/oat/arm64/base.vdex.7E2XPI.tmp 9:/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q==/oat/arm64/base.odex.swap.BG1X3H.tmp 10:/system/framework/org.apache.http.legacy.jar 
09-30 01:50:17.364  2158  2158 W dex2oat64: /apex/com.android.art/bin/dex2oat64 --zip-fd=6 --zip-location=/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q==/base.apk --oat-fd=7 --oat-location=/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q==/oat/arm64/base.odex --output-vdex-fd=8 --swap-fd=9 --class-loader-context-fds=10 --class-loader-context=PCL[]{PCL[/system/framework/org.apache.http.legacy.jar]} --classpath-dir=/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q== --instruction-set=arm64 --instruction-set-features=default --instruction-set-variant=generic --compiler-filter=verify --compilation-reason=install --compact-dex-level=none --max-image-block-size=524288 --resolve-startup-const-strings=true --generate-mini-debug-info --runtime-arg -Xdeny-art-apex-data-files --runtime-arg -Xtarget-sdk-version:36 --runtime-arg -Xhidden-api-policy:enabled --runtime-arg -Xms64m --runtime-arg -Xmx512m --comments=app-version-name:11.0.1,app-version-code:311000101,art-version:-1
09-30 01:50:17.365  2158  2158 I dex2oat64: /apex/com.android.art/bin/dex2oat64 --output-vdex-fd=8 --class-loader-context-fds=10 --class-loader-context=PCL[]{PCL[/system/framework/org.apache.http.legacy.jar]} --classpath-dir=/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q== --compiler-filter=verify --compilation-reason=install --compact-dex-level=none --max-image-block-size=524288 --resolve-startup-const-strings=true --generate-mini-debug-info --comments=app-version-name:11.0.1,app-version-code:311000101,art-version:-1
09-30 01:50:17.742   228   275 I ArtService: Dexopt result: [packageName = jp.konami.pesam] DexContainerFileDexoptResult{dexContainerFile=/data/app/~~JpkLShdMym0aZrHEoWiptQ==/jp.konami.pesam-3IrRLsJTUcuPEdfXleWA5Q==/base.apk, primaryAbi=true, abi=arm64-v8a, actualCompilerFilter=verify, status=PERFORMED, dex2oatWallTimeMillis=399, dex2oatCpuTimeMillis=1070, sizeBytes=682616, sizeBeforeBytes=0}
09-30 01:50:17.744   228   275 V BackupManagerService: [UserID:0] restoreAtInstall pkg=jp.konami.pesam token=1 restoreSet=0
09-30 01:50:17.753   854   903 D SessionCommitReceiver: Removing PromiseIcon for package: jp.konami.pesam, install reason: 0, alreadyAddedPromiseIcon: false
09-30 01:50:17.754   825   825 D CarrierSvcBindHelper: onPackageAdded: jp.konami.pesam
09-30 01:50:17.757   228   228 V GameManagerService_GamePackageConfiguration: No android.game_mode_config meta-data found for package jp.konami.pesam
09-30 01:50:17.757   228   228 V GameManagerService: Package configuration not found for jp.konami.pesam
09-30 01:50:17.760   603   603 I SafetyLabelChangedBroadcastReceiver: received broadcast packageName: jp.konami.pesam, current user: UserHandle{0}, packageChangeEvent: NEW_INSTALL, intent user: UserHandle{0}
09-30 01:50:17.765   228   569 I SdkSandboxManager: No SDKs used. Skipping SDK data reconcilation for CallingInfo{mUid=10087, mPackageName='jp.konami.pesam, mAppProcessToken='null'}
09-30 01:50:17.777   825   825 D CarrierSvcBindHelper: onPackageModified: jp.konami.pesam
09-30 01:50:36.418   228   657 I ActivityManager: Force stopping jp.konami.pesam appid=10087 user=0: from pid 2266
09-30 01:50:36.421   825   825 D CarrierSvcBindHelper: onHandleForceStop: [jp.konami.pesam]
09-30 01:50:36.497  2269  2269 D AndroidRuntime: >>>>>> START com.android.internal.os.RuntimeInit uid 0 <<<<<<
09-30 01:53:39.811   228   698 I ActivityManager: Force stopping jp.konami.pesam appid=10087 user=0: from pid 2921
09-30 01:53:39.813   825   825 D CarrierSvcBindHelper: onHandleForceStop: [jp.konami.pesam]
```
