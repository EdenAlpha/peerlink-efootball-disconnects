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
3f283a68522a9f5f59f84e971694fceef342784e07a9c7c2483727dcf6fe1ca8
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
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.en.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.es.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.fr.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.hi.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.in.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.it.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.ja.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.ko.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.my.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.pt.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.ru.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.th.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.tr.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.vi.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.xxxhdpi.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_config.zh.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_pad_it_0.apk
package:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/split_pad_it_1.apk
+ sudo docker exec redroid sh -c 'cmd package resolve-activity --brief -c android.intent.category.LAUNCHER jp.konami.pesam'
+ tail -5
priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
jp.konami.pesam/com.epicgames.ue4.SplashActivity
+ echo '--- direct am start as the fallback ---'
--- direct am start as the fallback ---
++ sudo docker exec redroid sh -c 'cmd package resolve-activity --brief -c android.intent.category.LAUNCHER jp.konami.pesam'
++ tr -d '\r'
++ grep -E '^jp\.konami\.pesam/'
++ tail -1
+ ACT=jp.konami.pesam/com.epicgames.ue4.SplashActivity
+ echo 'resolved launcher: [jp.konami.pesam/com.epicgames.ue4.SplashActivity]'
resolved launcher: [jp.konami.pesam/com.epicgames.ue4.SplashActivity]
+ '[' -n jp.konami.pesam/com.epicgames.ue4.SplashActivity ']'
+ sudo docker exec redroid sh -c 'am start -W -n jp.konami.pesam/com.epicgames.ue4.SplashActivity'
Starting: Intent { cmp=jp.konami.pesam/com.epicgames.ue4.SplashActivity }
Status: ok
LaunchState: COLD
Activity: jp.konami.pesam/com.epicgames.ue4.GameActivity
TotalTime: 471
WaitTime: 477
Complete
+ echo 'am start rc=0'
am start rc=0
+ GPID=
++ seq 1 24
+ for i in $(seq 1 24)
+ sleep 5
++ tr -d '\r'
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ awk '{print $1}'
+ GPID=4564
+ '[' -n 4564 ']'
+ echo 'game pid=4564 after 5s'
game pid=4564 after 5s
+ break
+ '[' -z 4564 ']'
+ echo '--- is libUE4.so actually mapped? ---'
--- is libUE4.so actually mapped? ---
+ sudo docker exec redroid sh -c 'grep -c libUE4 /proc/4564/maps 2>/dev/null'
4
+ sudo docker exec redroid sh -c 'grep libUE4 /proc/4564/maps 2>/dev/null | head -3'
e3dc1ec51000-e3dc21477000 r--p 00000000 08:01 6291554                    /data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/lib/arm64/libUE4.so
e3dc2147a000-e3dc277c3000 r-xp 02825000 08:01 6291554                    /data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/lib/arm64/libUE4.so
e3dc277c6000-e3dc28554000 r--p 08b6d000 08:01 6291554                    /data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/lib/arm64/libUE4.so
+ echo '--- reading the game'\''s memory from the host (no injection) ---'
--- reading the game's memory from the host (no injection) ---
+ GPID=4564
+ timeout 400 python3 kgs-login/scripts/read_paths.py --package jp.konami.pesam --seconds 300 --interval 3 --docker-exec 'sudo docker exec redroid'
+ SPID=22398
+ echo 'phase 3 reader pid 22398'
phase 3 reader pid 22398
++ seq 1 36
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4564
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=10s passes=0
0 gamepid=4564'
  phase3 t=10s passes=0
0 gamepid=4564
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4564 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4564
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=20s passes=0
0 gamepid=4564'
  phase3 t=20s passes=0
0 gamepid=4564
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4564 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4564
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=30s passes=0
0 gamepid=4564'
  phase3 t=30s passes=0
0 gamepid=4564
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4564 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4564
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=40s passes=0
0 gamepid=4564'
  phase3 t=40s passes=0
0 gamepid=4564
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4564 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4564
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=50s passes=0
0 gamepid=4564'
  phase3 t=50s passes=0
0 gamepid=4564
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4564 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ awk '{print $1}'
++ tr -d '\r'
+ alive=4564
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=60s passes=0
0 gamepid=4564'
  phase3 t=60s passes=0
0 gamepid=4564
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4564 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4564
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
++ echo 0
+ echo '  phase3 t=70s passes=0
0 gamepid=4564'
  phase3 t=70s passes=0
0 gamepid=4564
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4564 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4564
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
+ echo '  phase3 t=80s passes=1 gamepid=4564'
  phase3 t=80s passes=1 gamepid=4564
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4564 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4564
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
+ echo '  phase3 t=90s passes=1 gamepid=4564'
  phase3 t=90s passes=1 gamepid=4564
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4564 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ tr -d '\r'
++ awk '{print $1}'
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
+ alive=4564
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
+ echo '  phase3 t=100s passes=1 gamepid=4564'
  phase3 t=100s passes=1 gamepid=4564
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4564 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4564
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
+ echo '  phase3 t=110s passes=1 gamepid=4564'
  phase3 t=110s passes=1 gamepid=4564
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4564 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ alive=4564
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
+ echo '  phase3 t=120s passes=2 gamepid=4564'
  phase3 t=120s passes=2 gamepid=4564
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4564 ']'
+ for i in $(seq 1 36)
+ sleep 10
++ tr -d '\r'
++ awk '{print $1}'
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
+ alive=4564
++ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
+ echo '  phase3 t=130s passes=2 gamepid=4564'
  phase3 t=130s passes=2 gamepid=4564
+ sudo docker exec redroid /system/bin/input tap 360 640
+ sudo docker exec redroid /system/bin/input keyevent 66
+ '[' -n 4564 ']'
+ for i in $(seq 1 36)
+ sleep 10
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
09-30 05:00:53.220  1179  1754 D MediaGrants: Removed 0 media_grants for 0 user for jp.konami.pesam. Reason: Mode changed: android:read_external_storage
09-30 05:00:53.221  1179  1754 D MediaGrants: Removed 0 media_grants for 0 user for jp.konami.pesam. Reason: Mode changed: android:read_external_storage
09-30 05:00:53.222  1179  1754 D MediaGrants: Removed 0 media_grants for 0 user for jp.konami.pesam. Reason: Mode changed: android:read_external_storage
09-30 05:00:53.244  2162  2163 W ziparchive: Unable to open '/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/base.dm': No such file or directory
09-30 05:00:53.244  2162  2163 W ziparchive: Unable to open '/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/base.dm': No such file or directory
09-30 05:00:53.247  2162  2163 I artd    : Running dex2oat: /apex/com.android.art/bin/art_exec --drop-capabilities --set-task-profile=Dex2OatBootComplete --set-priority=background --keep-fds=6:7:8:9:10 -- /apex/com.android.art/bin/dex2oat64 --zip-fd=6 --zip-location=/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/base.apk --oat-fd=7 --oat-location=/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/oat/arm64/base.odex --output-vdex-fd=8 --swap-fd=9 --class-loader-context-fds=10 --class-loader-context=PCL[]{PCL[/system/framework/org.apache.http.legacy.jar]} --classpath-dir=/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA== --instruction-set=arm64 --instruction-set-features=default --instruction-set-variant=generic --compiler-filter=verify --compilation-reason=install --compact-dex-level=none --max-image-block-size=524288 --resolve-startup-const-strings=true --generate-mini-debug-info --runtime-arg -Xdeny-art-apex-data-files --runtime-arg -Xtarget-sdk-version:36 --runtime-arg -Xhidden-api-policy:enabled --runtime-arg -Xms64m --runtime-arg -Xmx512m --comments=app-version-name:11.0.1,app-version-code:311000101,art-version:-1
09-30 05:00:53.247  2162  2163 I artd    : Opened FDs: 6:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/base.apk 7:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/oat/arm64/base.odex.nF9szO.tmp 8:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/oat/arm64/base.vdex.jpccuY.tmp 9:/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/oat/arm64/base.odex.swap.XXiGN5.tmp 10:/system/framework/org.apache.http.legacy.jar 
09-30 05:00:53.265  2164  2164 W dex2oat64: /apex/com.android.art/bin/dex2oat64 --zip-fd=6 --zip-location=/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/base.apk --oat-fd=7 --oat-location=/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/oat/arm64/base.odex --output-vdex-fd=8 --swap-fd=9 --class-loader-context-fds=10 --class-loader-context=PCL[]{PCL[/system/framework/org.apache.http.legacy.jar]} --classpath-dir=/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA== --instruction-set=arm64 --instruction-set-features=default --instruction-set-variant=generic --compiler-filter=verify --compilation-reason=install --compact-dex-level=none --max-image-block-size=524288 --resolve-startup-const-strings=true --generate-mini-debug-info --runtime-arg -Xdeny-art-apex-data-files --runtime-arg -Xtarget-sdk-version:36 --runtime-arg -Xhidden-api-policy:enabled --runtime-arg -Xms64m --runtime-arg -Xmx512m --comments=app-version-name:11.0.1,app-version-code:311000101,art-version:-1
09-30 05:00:53.265  2164  2164 I dex2oat64: /apex/com.android.art/bin/dex2oat64 --output-vdex-fd=8 --class-loader-context-fds=10 --class-loader-context=PCL[]{PCL[/system/framework/org.apache.http.legacy.jar]} --classpath-dir=/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA== --compiler-filter=verify --compilation-reason=install --compact-dex-level=none --max-image-block-size=524288 --resolve-startup-const-strings=true --generate-mini-debug-info --comments=app-version-name:11.0.1,app-version-code:311000101,art-version:-1
09-30 05:00:53.665   234   281 I ArtService: Dexopt result: [packageName = jp.konami.pesam] DexContainerFileDexoptResult{dexContainerFile=/data/app/~~rNe16zSwXM08fZkJxWXi4Q==/jp.konami.pesam-iylSK8mkvrCqf1RPwrLjuA==/base.apk, primaryAbi=true, abi=arm64-v8a, actualCompilerFilter=verify, status=PERFORMED, dex2oatWallTimeMillis=424, dex2oatCpuTimeMillis=1140, sizeBytes=682616, sizeBeforeBytes=0}
09-30 05:00:53.668   234   281 V BackupManagerService: [UserID:0] restoreAtInstall pkg=jp.konami.pesam token=1 restoreSet=0
09-30 05:00:53.681   234   234 V GameManagerService_GamePackageConfiguration: No android.game_mode_config meta-data found for package jp.konami.pesam
09-30 05:00:53.681   854   906 D SessionCommitReceiver: Removing PromiseIcon for package: jp.konami.pesam, install reason: 0, alreadyAddedPromiseIcon: false
09-30 05:00:53.681   820   820 D CarrierSvcBindHelper: onPackageAdded: jp.konami.pesam
09-30 05:00:53.681   234   575 I SdkSandboxManager: No SDKs used. Skipping SDK data reconcilation for CallingInfo{mUid=10087, mPackageName='jp.konami.pesam, mAppProcessToken='null'}
09-30 05:00:53.681   234   234 V GameManagerService: Package configuration not found for jp.konami.pesam
09-30 05:00:53.686   605   605 I SafetyLabelChangedBroadcastReceiver: received broadcast packageName: jp.konami.pesam, current user: UserHandle{0}, packageChangeEvent: NEW_INSTALL, intent user: UserHandle{0}
09-30 05:00:53.696   820   820 D CarrierSvcBindHelper: onPackageModified: jp.konami.pesam
09-30 05:01:12.221   234   696 I ActivityManager: Force stopping jp.konami.pesam appid=10087 user=0: from pid 2270
09-30 05:01:12.223   820   820 D CarrierSvcBindHelper: onHandleForceStop: [jp.konami.pesam]
09-30 05:01:12.308  2273  2273 D AndroidRuntime: >>>>>> START com.android.internal.os.RuntimeInit uid 0 <<<<<<
09-30 05:04:15.909   234  1022 I ActivityManager: Force stopping jp.konami.pesam appid=10087 user=0: from pid 2929
09-30 05:04:15.911   820   820 D CarrierSvcBindHelper: onHandleForceStop: [jp.konami.pesam]
```
