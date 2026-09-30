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
2eb7666d6affee7d01938598ba08b98339a0932facd8a574afeacfad53a024ee
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
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=45s'
  waiting for game process t=45s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=50s'
  waiting for game process t=50s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=55s'
  waiting for game process t=55s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=60s'
  waiting for game process t=60s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=65s'
  waiting for game process t=65s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=70s'
  waiting for game process t=70s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=75s'
  waiting for game process t=75s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=80s'
  waiting for game process t=80s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=85s'
  waiting for game process t=85s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=90s'
  waiting for game process t=90s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=95s'
  waiting for game process t=95s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=100s'
  waiting for game process t=100s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=105s'
  waiting for game process t=105s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=110s'
  waiting for game process t=110s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=115s'
  waiting for game process t=115s
+ for i in $(seq 1 24)
+ sleep 5
++ sudo docker exec redroid sh -c 'pidof jp.konami.pesam 2>/dev/null'
++ tr -d '\r'
++ awk '{print $1}'
+ GPID=
+ '[' -n '' ']'
+ echo '  waiting for game process t=120s'
  waiting for game process t=120s
+ '[' -z '' ']'
+ echo '=== GAME PROCESS NEVER APPEARED ==='
=== GAME PROCESS NEVER APPEARED ===
+ echo 'the launch output above is the diagnosis; read it before'
the launch output above is the diagnosis; read it before
+ echo 'concluding anything about routes.'
concluding anything about routes.
+ sudo docker exec redroid sh -c 'ps -A | head -30'
USER             PID    PPID        VSZ    RSS WCHAN            ADDR S NAME                       
root               1       0   10978292  11184 ep_poll             0 S init
root               8       1   10998040  10336 poll_schedule_timeout.constprop.0 0 S init
root              15       1   11026840  10552 poll_schedule_timeout.constprop.0 0 S ueventd
prng_seeder       18       1   10944972   7572 futex_do_wait       0 S prng_seeder
logd              22       1   10968432   7528 sigsuspend          0 S logd
lmkd              23       1   10898432   4324 ep_poll             0 S lmkd
system            24       1   10828704   6048 ep_poll             0 S servicemanager
system            25       1   10898200   7488 ep_poll             0 S hwservicemanager
root              38       1   10937740   9960 binder_wait_for_work 0 S vold
system            43       1   10982548   5828 binder_wait_for_work 0 S android.system.suspend-service
keystore          44       1   11023204  19268 binder_wait_for_work 0 S keystore2
system            45       1   10873320   8284 binder_wait_for_work 0 S android.hardware.keymaster@4.1-service
tombstoned        55       1   10790868   3424 ep_poll             0 S tombstoned
system            91       1   10881920   4608 binder_wait_for_work 0 S android.hidl.allocator@1.0-service
audioserver       92       1   11048616  12164 binder_wait_for_work 0 S android.hardware.audio.service
system            94       1   10857860   6512 binder_wait_for_work 0 S android.hardware.gatekeeper@1.0-service.software
system            97       1   10941272   5484 binder_wait_for_work 0 S android.hardware.graphics.allocator@2.0-service
system            98       1   10951400   8384 binder_wait_for_work 0 S android.hardware.graphics.composer@2.1-service
system            99       1   10834216   7164 ep_poll             0 S android.hardware.health-service.example
system           100       1   10956788   5240 binder_wait_for_work 0 S android.hardware.thermal@2.0-service.mock
media            103       1   10846868   5880 binder_wait_for_work 0 S android.hardware.cas-service.example
nobody           110       1   10860848   5508 binder_wait_for_work 0 S android.hardware.power-service.example
audioserver      111       1   11532840  33464 binder_wait_for_work 0 S audioserver
credstore        112       1   11077548  11016 binder_wait_for_work 0 S credstore
gpu_service      113       1   11076032   9752 binder_wait_for_work 0 S gpuservice
system           114       1   11808224  69936 ep_poll             0 S surfaceflinger
shell            133       1   11093392  11324 ep_poll             0 S adbd
nobody           135       1   10898756   4332 poll_schedule_timeout.constprop.0 0 S traced_probes
nobody           143       1   10820420   4568 poll_schedule_timeout.constprop.0 0 S traced
+ sudo docker exec redroid logcat -d -t 300
+ grep -iE 'konami|pesam|unity|ActivityManager.*(START|crash|died)|FATAL|AndroidRuntime|libUE4|Vulkan|EGL|ANR'
+ tail -50
09-30 01:43:03.311   229   687 I ActivityManager: Force stopping jp.konami.pesam appid=10087 user=0: from pid 4529
09-30 01:43:03.314   812   812 D CarrierSvcBindHelper: onHandleForceStop: [jp.konami.pesam]
09-30 01:43:03.407  4532  4532 D AndroidRuntime: >>>>>> START com.android.internal.os.RuntimeInit uid 0 <<<<<<
09-30 01:43:03.554   229  1569 I ActivityTaskManager: START u0 {flg=0x10000000 cmp=jp.konami.pesam/com.unity3d.player.UnityPlayerActivity} with LAUNCH_MULTIPLE from uid 0 result code=-92
+ echo '=== graphics ==='
=== graphics ===
+ sudo docker exec redroid sh -c 'ls /vendor/lib64/libvulkan.so /vendor/lib64/hw/vulkan.*.so 2>&1'
+ head
ls: /vendor/lib64/libvulkan.so: No such file or directory
/vendor/lib64/hw/vulkan.broadcom.so
/vendor/lib64/hw/vulkan.freedreno.so
/vendor/lib64/hw/vulkan.lvp.so
/vendor/lib64/hw/vulkan.nouveau.so
/vendor/lib64/hw/vulkan.panfrost.so
/vendor/lib64/hw/vulkan.pastel.so
/vendor/lib64/hw/vulkan.radeon.so
/vendor/lib64/hw/vulkan.virtio.so
+ echo '=== end ==='
=== end ===
+ echo 'GAME LAUNCH FAILED'
GAME LAUNCH FAILED
+ echo '--- what frida itself said (this is what diagnosed the last run) ---'
--- what frida itself said (this is what diagnosed the last run) ---
+ head -14 /tmp/kgs/scan.log
+ true
+ echo '--- scanner output ---'
--- scanner output ---
+ grep -E '^\[scan\]|path=' /tmp/kgs/scan.log
+ head -80
grep: /tmp/kgs/scan.log: No such file or directory
+ echo '--- pass count: 0 WITH a frida error above means the scanner never'
--- pass count: 0 WITH a frida error above means the scanner never
+ echo '    ran, which is NOT the same as the game building no request ---'
    ran, which is NOT the same as the game building no request ---
+ grep -c '^\[scan\] pass' /tmp/kgs/scan.log
+ echo 0
0
+ tail -20 /tmp/kgs/scan.log
tail: cannot open '/tmp/kgs/scan.log' for reading: No such file or directory
+ true
+ cp -f /tmp/kgs/scan.log /scan-paths.log
+ true
+ sudo docker exec redroid logcat -d -t 400
+ echo '=== logcat phase 3 (filtered) ==='
=== logcat phase 3 (filtered) ===
+ grep -iE 'konami|pesam|FATAL|AndroidRuntime|libUE4|Vulkan|EGL' /tmp/kgs/logcat-p3.txt
+ tail -40
09-30 01:36:34.456   229   687 I ActivityManager: Force stopping jp.konami.pesam appid=10087 user=0: from pid 2925
09-30 01:36:34.458   812   812 D CarrierSvcBindHelper: onHandleForceStop: [jp.konami.pesam]
09-30 01:43:03.311   229   687 I ActivityManager: Force stopping jp.konami.pesam appid=10087 user=0: from pid 4529
09-30 01:43:03.314   812   812 D CarrierSvcBindHelper: onHandleForceStop: [jp.konami.pesam]
09-30 01:43:03.407  4532  4532 D AndroidRuntime: >>>>>> START com.android.internal.os.RuntimeInit uid 0 <<<<<<
09-30 01:43:03.554   229  1569 I ActivityTaskManager: START u0 {flg=0x10000000 cmp=jp.konami.pesam/com.unity3d.player.UnityPlayerActivity} with LAUNCH_MULTIPLE from uid 0 result code=-92
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
-rw-r--r-- 1 root root 24 Sep 30 01:36 /tmp/kgs/game.pcap
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
09-30 01:33:12.149   229   277 I ArtService: Dexopt result: [packageName = jp.konami.pesam] DexContainerFileDexoptResult{dexContainerFile=/data/app/~~JG6R11CDtMFTi1fYltFwbQ==/jp.konami.pesam--qrN7xqSOMB3uXTC9NW0wA==/base.apk, primaryAbi=true, abi=arm64-v8a, actualCompilerFilter=verify, status=PERFORMED, dex2oatWallTimeMillis=431, dex2oatCpuTimeMillis=1180, sizeBytes=682616, sizeBeforeBytes=0}
09-30 01:33:12.152   229   277 V BackupManagerService: [UserID:0] restoreAtInstall pkg=jp.konami.pesam token=1 restoreSet=0
09-30 01:33:12.165   229   565 I SdkSandboxManager: No SDKs used. Skipping SDK data reconcilation for CallingInfo{mUid=10087, mPackageName='jp.konami.pesam, mAppProcessToken='null'}
09-30 01:33:12.167   812   812 D CarrierSvcBindHelper: onPackageAdded: jp.konami.pesam
09-30 01:33:12.172   229   229 V GameManagerService_GamePackageConfiguration: No android.game_mode_config meta-data found for package jp.konami.pesam
09-30 01:33:12.173   598   598 I SafetyLabelChangedBroadcastReceiver: received broadcast packageName: jp.konami.pesam, current user: UserHandle{0}, packageChangeEvent: NEW_INSTALL, intent user: UserHandle{0}
09-30 01:33:12.173   229   229 V GameManagerService: Package configuration not found for jp.konami.pesam
09-30 01:33:12.174   846   898 D SessionCommitReceiver: Removing PromiseIcon for package: jp.konami.pesam, install reason: 0, alreadyAddedPromiseIcon: false
09-30 01:33:12.186   812   812 D CarrierSvcBindHelper: onPackageModified: jp.konami.pesam
09-30 01:33:30.713   229   900 I ActivityManager: Force stopping jp.konami.pesam appid=10087 user=0: from pid 2269
09-30 01:33:30.717   812   812 D CarrierSvcBindHelper: onHandleForceStop: [jp.konami.pesam]
09-30 01:33:30.805  2272  2272 D AndroidRuntime: >>>>>> START com.android.internal.os.RuntimeInit uid 0 <<<<<<
09-30 01:36:34.456   229   687 I ActivityManager: Force stopping jp.konami.pesam appid=10087 user=0: from pid 2925
09-30 01:36:34.458   812   812 D CarrierSvcBindHelper: onHandleForceStop: [jp.konami.pesam]
```
