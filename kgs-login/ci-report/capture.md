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
9e8adce375a2019b0e9034cfcf4229969f05b1811201435b9797b5ff0060b7a2
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
/vendor/lib64/hw/vulkan.lvp.so
/vendor/lib64/hw/vulkan.nouveau.so
/vendor/lib64/hw/vulkan.panfrost.so
/vendor/lib64/hw/vulkan.pastel.so
/vendor/lib64/hw/vulkan.radeon.so
/vendor/lib64/hw/vulkan.virtio.so
+ true
+ sudo docker exec redroid sh -c 'dumpsys SurfaceFlinger 2>/dev/null | grep -iE "GLES|Vulkan|EGL" | head -8'
Sync configuration: [using: EGL_KHR_fence_sync EGL_KHR_wait_sync]
EGL implementation : 1.5 Android META-EGL
EGL_ANDROID_front_buffer_auto_refresh EGL_ANDROID_get_native_client_buffer EGL_ANDROID_presentation_time EGL_EXT_surface_CTA861_3_metadata EGL_EXT_surface_SMPTE2086_metadata EGL_KHR_get_all_proc_addresses EGL_KHR_swap_buffers_with_damage EGL_ANDROID_image_native_buffer EGL_ANDROID_recordable EGL_EXT_buffer_age EGL_EXT_create_context_robustness EGL_EXT_image_gl_colorspace EGL_EXT_pixel_format_float EGL_IMG_context_priority EGL_KHR_create_context EGL_KHR_fence_sync EGL_KHR_gl_colorspace EGL_KHR_gl_renderbuffer_image EGL_KHR_gl_texture_2D_image EGL_KHR_gl_texture_cubemap_image EGL_KHR_image EGL_KHR_image_base EGL_KHR_no_config_context EGL_KHR_partial_update EGL_KHR_reusable_sync EGL_KHR_surfaceless_context EGL_KHR_wait_sync 
GLES: Google Inc. (Google), ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (LLVM 10.0.0) (0x0000C0DE)), SwiftShader driver-5.0.0), OpenGL ES 3.1.0 (ANGLE 2.1.1 git hash: 35552d8fca88)
GL_AMD_performance_monitor GL_ANGLE_base_vertex_base_instance GL_ANGLE_base_vertex_base_instance_shader_builtin GL_ANGLE_client_arrays GL_ANGLE_clip_cull_distance GL_ANGLE_compressed_texture_etc GL_ANGLE_copy_texture_3d GL_ANGLE_depth_texture GL_ANGLE_framebuffer_blit GL_ANGLE_framebuffer_multisample GL_ANGLE_get_image GL_ANGLE_get_serialized_context_string GL_ANGLE_get_tex_level_parameter GL_ANGLE_instanced_arrays GL_ANGLE_memory_object_flags GL_ANGLE_memory_size GL_ANGLE_multi_draw GL_ANGLE_pack_reverse_row_order GL_ANGLE_polygon_mode GL_ANGLE_program_cache_control GL_ANGLE_read_only_depth_stencil_feedback_loops GL_ANGLE_relaxed_vertex_attribute_type GL_ANGLE_renderability_validation GL_ANGLE_request_extension GL_ANGLE_rgbx_internal_format GL_ANGLE_robust_client_memory GL_ANGLE_robust_fragment_shader_output GL_ANGLE_shader_pixel_local_storage GL_ANGLE_shader_pixel_local_storage_coherent GL_ANGLE_stencil_texturing GL_ANGLE_texture_compression_dxt3 GL_ANGLE_texture_compression_dxt5 GL_ANGLE_texture_multisample GL_ANGLE_texture_usage GL_ANGLE_vulkan_image GL_ANGLE_yuv_internal_format GL_APPLE_clip_distance GL_ARM_shader_framebuffer_fetch GL_CHROMIUM_bind_generates_resource GL_CHROMIUM_bind_uniform_location GL_CHROMIUM_copy_compressed_texture GL_CHROMIUM_copy_texture GL_CHROMIUM_lose_context GL_EXT_EGL_image_array GL_EXT_EGL_image_external_wrap_modes GL_EXT_EGL_image_storage GL_EXT_base_instance GL_EXT_blend_minmax GL_EXT_buffer_storage GL_EXT_clip_control GL_EXT_clip_cull_distance GL_EXT_color_buffer_float GL_EXT_color_buffer_half_float GL_EXT_compressed_ETC1_RGB8_sub_texture GL_EXT_conservative_depth GL_EXT_copy_image GL_EXT_debug_label GL_EXT_debug_marker GL_EXT_depth_clamp GL_EXT_discard_framebuffer GL_EXT_disjoint_timer_query GL_EXT_draw_buffers GL_EXT_draw_buffers_indexed GL_EXT_draw_elements_base_vertex GL_EXT_external_buffer GL_EXT_float_blend GL_EXT_frag_depth GL_EXT_instanced_arrays GL_EXT_map_buffer_range GL_EXT_memory_object GL_EXT_multi_draw_indirect GL_EXT_multisample_compatibility GL_EXT_occlusion_query_boolean GL_EXT_polygon_offset_clamp GL_EXT_primitive_bounding_box GL_EXT_read_format_bgra GL_EXT_robustness GL_EXT_sRGB GL_EXT_sRGB_write_control GL_EXT_semaphore GL_EXT_semaphore_fd GL_EXT_separate_shader_objects GL_EXT_shader_framebuffer_fetch GL_EXT_shader_framebuffer_fetch_non_coherent GL_EXT_shader_io_blocks GL_EXT_shader_non_constant_global_initializers GL_EXT_shader_texture_lod GL_EXT_shadow_samplers GL_EXT_texture_border_clamp GL_EXT_texture_buffer GL_EXT_texture_compression_bptc GL_EXT_texture_compression_dxt1 GL_EXT_texture_compression_rgtc GL_EXT_texture_compression_s3tc_srgb GL_EXT_texture_cube_map_array GL_EXT_texture_filter_anisotropic GL_EXT_texture_format_BGRA8888 GL_EXT_texture_mirror_clamp_to_edge GL_EXT_texture_norm16 GL_EXT_texture_rg GL_EXT_texture_sRGB_R8 GL_EXT_texture_sRGB_RG8 GL_EXT_texture_sRGB_decode GL_EXT_texture_storage GL_EXT_texture_type_2_10_10_10_REV GL_EXT_unpack_subimage GL_KHR_blend_equation_advanced GL_KHR_debug GL_KHR_texture_compression_astc_ldr GL_NV_depth_buffer_float2 GL_NV_fence GL_NV_framebuffer_blit GL_NV_pack_subimage GL_NV_pixel_buffer_object GL_NV_polygon_mode GL_NV_read_depth GL_NV_read_depth_stencil GL_NV_read_stencil GL_NV_shader_noperspective_interpolation GL_OES_EGL_image GL_OES_EGL_image_external GL_OES_EGL_image_external_essl3 GL_OES_EGL_sync GL_OES_compressed_EAC_R11_signed_texture GL_OES_compressed_EAC_R11_unsigned_texture GL_OES_compressed_EAC_RG11_signed_texture GL_OES_compressed_EAC_RG11_unsigned_texture GL_OES_compressed_ETC1_RGB8_texture GL_OES_compressed_ETC2_RGB8_texture GL_OES_compressed_ETC2_RGBA8_texture GL_OES_compressed_ETC2_punchthroughA_RGBA8_texture GL_OES_compressed_ETC2_punchthroughA_sRGB8_alpha_texture GL_OES_compressed_ETC2_sRGB8_alpha8_texture GL_OES_compressed_ETC2_sRGB8_texture GL_OES_depth24 GL_OES_depth32 GL_OES_depth_texture GL_OES_depth_texture_cube_map GL_OES_draw_buffers_indexed GL_OES_draw_elements_base_vertex GL_OES_element_index_uint GL_OES_fbo_render_mipmap GL_OES_get_program_binary GL_OES_mapbuffer GL_OES_packed_depth_stencil GL_OES_primitive_bounding_box GL_OES_rgb8_rgba8 GL_OES_sample_shading GL_OES_sample_variables GL_OES_shader_image_atomic GL_OES_shader_io_blocks GL_OES_shader_multisample_interpolation GL_OES_standard_derivatives GL_OES_surfaceless_context GL_OES_texture_3D GL_OES_texture_border_clamp GL_OES_texture_buffer GL_OES_texture_cube_map_array GL_OES_texture_float GL_OES_texture_float_linear GL_OES_texture_half_float GL_OES_texture_half_float_linear GL_OES_texture_npot GL_OES_texture_stencil8 GL_OES_texture_storage_multisample_2d_array GL_OES_vertex_array_object GL_OES_vertex_half_float GL_OES_vertex_type_10_10_10_2 GL_OVR_multiview GL_OVR_multiview2 
+ sudo docker exec redroid sh -c 'getprop | grep -iE "gpu|egl|gles|vulkan|hardware"'
[debug.renderengine.backend]: [gles]
[init.svc.gpu]: [running]
[init.svc_debug_pid.gpu]: [112]
[persist.graphics.egl]: []
[ro.boot.hardware]: [redroid]
[ro.boottime.gpu]: [62995286556]
[ro.hardware]: [redroid]
[ro.hardware.egl]: [angle]
[ro.hardware.gralloc]: [redroid]
[ro.hardware.vulkan]: [pastel]
[ro.hwui.use_vulkan]: []
[ro.opengles.version]: [196610]
+ cd /tmp/kgs
++ whoami
++ pwd
+ echo 'whoami=runner cwd=/tmp/kgs'
whoami=runner cwd=/tmp/kgs
+ touch /tmp/kgs/probe
+ echo 'workdir writable'
workdir writable
+ '[' -s /tmp/kgs/jp.konami.pesam.xapk ']'
+ echo 'cache miss, downloading'
cache miss, downloading
+ curl -sS -o /dev/null -w 'github.com HTTP %{http_code}\n' --max-time 30 https://github.com/
github.com HTTP 200
+ got=
+ for url in "https://github.com/EFForg/apkeep/releases/download/1.0.0/apkeep-aarch64-unknown-linux-gnu" "https://github.com/EFForg/apkeep/releases/download/1.0.0/apkeep-aarch64-unknown-linux-gnu.static"
+ echo 'trying https://github.com/EFForg/apkeep/releases/download/1.0.0/apkeep-aarch64-unknown-linux-gnu'
trying https://github.com/EFForg/apkeep/releases/download/1.0.0/apkeep-aarch64-unknown-linux-gnu
+ curl -fsSL --max-time 300 -o /tmp/kgs/apkeep https://github.com/EFForg/apkeep/releases/download/1.0.0/apkeep-aarch64-unknown-linux-gnu
+ got=https://github.com/EFForg/apkeep/releases/download/1.0.0/apkeep-aarch64-unknown-linux-gnu
+ break
+ '[' '!' -s /tmp/kgs/apkeep ']'
+ chmod +x /tmp/kgs/apkeep
+ echo 11670
+ /tmp/kgs/apkeep -a jp.konami.pesam -d apk-pure /tmp/kgs
+ sleep 30
+ cat /tmp/kgs/apkeep.log
Downloading jp.konami.pesam...
jp.konami.pesam downloaded successfully!
+ ls -la /tmp/kgs/
+ head
total 856476
drwxr-xr-x  2 runner runner      4096 Sep 30 00:00 .
drwxrwxrwt 14 root   root        4096 Sep 30 00:00 ..
-rwxr-xr-x  1 runner runner  14690688 Sep 30 00:00 apkeep
-rw-r--r--  1 runner runner        72 Sep 30 00:00 apkeep.log
-rw-r--r--  1 runner runner         6 Sep 30 00:00 apkeep.pid
-rw-r--r--  1 runner runner 862294575 Sep 30 00:00 jp.konami.pesam.xapk
-rw-r--r--  1 runner runner     11213 Sep 30 00:00 pipeline.log
-rw-r--r--  1 runner runner         0 Sep 30 00:00 probe
-rw-r--r--  1 runner runner      9884 Sep 30 00:00 step01.log
+ python3 -m pip install --quiet --break-system-packages frida-tools
++ python3 -c 'import frida; print(frida.__version__)'
+ FRIDA_VER=17.19.0
+ echo 'frida client version: 17.19.0'
frida client version: 17.19.0
+ '[' -n 17.19.0 ']'
+ ok=0
+ url=https://github.com/frida/frida/releases/download/17.19.0/frida-server-17.19.0-android-arm64.xz
+ echo 'trying https://github.com/frida/frida/releases/download/17.19.0/frida-server-17.19.0-android-arm64.xz'
trying https://github.com/frida/frida/releases/download/17.19.0/frida-server-17.19.0-android-arm64.xz
+ curl -fsSL --max-time 300 -o /tmp/kgs/frida-server.xz https://github.com/frida/frida/releases/download/17.19.0/frida-server-17.19.0-android-arm64.xz
+ ok=1
+ echo 'curl rc=0 ok=1'
curl rc=0 ok=1
+ '[' 1 '!=' 1 ']'
+ xz -d -f /tmp/kgs/frida-server.xz
+ ls -la /tmp/kgs/frida-server
-rw-r--r-- 1 runner runner 59071912 Sep 30 00:00 /tmp/kgs/frida-server
+ sudo docker cp /tmp/kgs/frida-server redroid:/data/local/tmp/frida-server
+ sudo docker exec redroid chmod 755 /data/local/tmp/frida-server
+ sudo docker exec redroid mkdir -p /data/local/tmp/kgs
+ sudo docker exec -d redroid sh -c '/data/local/tmp/frida-server > /data/local/tmp/frida.out 2>&1'
+ sleep 8
+ echo '--- frida-server output ---'
--- frida-server output ---
+ sudo docker exec redroid sh -c 'cat /data/local/tmp/frida.out 2>&1'
Aborted (core dumped) 
+ echo '--- process list ---'
--- process list ---
+ sudo docker exec redroid sh -c 'ps -A | grep -i frida'
+ echo 'frida-server NOT running'
frida-server NOT running
+ echo '--- selinux ---'
--- selinux ---
+ sudo docker exec redroid sh -c 'getenforce 2>&1'
Disabled
+ echo '--- port ---'
--- port ---
+ nc -zv 127.0.0.1 27042
Connection to 127.0.0.1 27042 port [tcp/*] succeeded!
+ echo 'frida-server REACHABLE'
frida-server REACHABLE
+ echo '--- host arch sanity (a wrong-arch binary fails exactly like this) ---'
--- host arch sanity (a wrong-arch binary fails exactly like this) ---
+ file /tmp/kgs/frida-server
/tmp/kgs/frida-server: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /system/bin/linker64, stripped
+ i=0
+ '[' 0 -lt 160 ']'
+ '[' -f /tmp/kgs/jp.konami.pesam.xapk ']'
+ break
++ head -1
++ ls -1 /tmp/kgs/jp.konami.pesam.xapk '/tmp/kgs/*.apkm' '/tmp/kgs/*.apks'
+ XAPK=/tmp/kgs/jp.konami.pesam.xapk
+ '[' -z /tmp/kgs/jp.konami.pesam.xapk ']'
++ stat -c %s /tmp/kgs/jp.konami.pesam.xapk
+ SZ=862294575
+ echo 'archive: /tmp/kgs/jp.konami.pesam.xapk  (862294575 bytes)'
archive: /tmp/kgs/jp.konami.pesam.xapk  (862294575 bytes)
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
-rw-r--r-- 1 radio radio  22347497 2026-09-30 00:01 /data/local/tmp/splits/base.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 /data/local/tmp/splits/split_config.ar.apk
-rw-r--r-- 1 radio radio  57148181 2026-09-30 00:01 /data/local/tmp/splits/split_config.arm64_v8a.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 /data/local/tmp/splits/split_config.de.apk
-rw-r--r-- 1 radio radio     37074 2026-09-30 00:01 /data/local/tmp/splits/split_config.en.apk
-rw-r--r-- 1 radio radio     24786 2026-09-30 00:01 /data/local/tmp/splits/split_config.es.apk
-rw-r--r-- 1 radio radio     24786 2026-09-30 00:01 /data/local/tmp/splits/split_config.fr.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 /data/local/tmp/splits/split_config.hi.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 /data/local/tmp/splits/split_config.in.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 /data/local/tmp/splits/split_config.it.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 /data/local/tmp/splits/split_config.ja.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 /data/local/tmp/splits/split_config.ko.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 /data/local/tmp/splits/split_config.my.apk
-rw-r--r-- 1 radio radio     24786 2026-09-30 00:01 /data/local/tmp/splits/split_config.pt.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 /data/local/tmp/splits/split_config.ru.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 /data/local/tmp/splits/split_config.th.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 /data/local/tmp/splits/split_config.tr.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 /data/local/tmp/splits/split_config.vi.apk
-rw-r--r-- 1 radio radio    198371 2026-09-30 00:01 /data/local/tmp/splits/split_config.xxxhdpi.apk
-rw-r--r-- 1 radio radio     28882 2026-09-30 00:01 /data/local/tmp/splits/split_config.zh.apk
-rw-r--r-- 1 radio radio 386375435 2026-09-30 00:01 /data/local/tmp/splits/split_pad_it_0.apk
-rw-r--r-- 1 radio radio 395420368 2026-09-30 00:01 /data/local/tmp/splits/split_pad_it_1.apk
+ echo '--- pm subcommands available ---'
--- pm subcommands available ---
+ sudo docker exec redroid sh -c 'pm help 2>&1 | grep -iE "install" | head -12'
      -i: see the installer for the packages
      -u: also include uninstalled packages
  install [-rtfdg] [-i PACKAGE] [--user USER_ID|all|current]
       [-p INHERIT_PACKAGE] [--install-location 0/1/2]
       [--install-reason 0/1/2/3/4] [--originating-uri URI]
    Install an application.  Must provide the apk data to install, either as
      -i: specify package name of installer owning the app
      -f: install application on internal flash
      -p: partial application install (new split on top of existing pkg)
      --user: install under the given user.
      --dont-kill: installing a new feature split, don't kill running app
      --restrict-permissions: don't whitelist restricted permissions at install
+ echo '--- install via session api ---'
--- install via session api ---
+ timeout 1800 sudo docker exec redroid sh -c '
  cd /data/local/tmp/splits || exit 1
  SESSION=$(pm install-create -r | tr -d "\r")
  echo "session=[$SESSION]"
  case "$SESSION" in
    ""|*[!0-9]*) echo "could not create a session"; exit 1 ;;
  esac
  for f in ./*.apk; do
    echo "  write $f"
    pm install-write "$SESSION" "$(basename $f)" "$f" || echo "  write FAILED $f"
  done
  pm install-commit "$SESSION"
'
+ tail -40
session=[Success: created install session [1020103925]]
could not create a session
+ echo '--- package state ---'
--- package state ---
+ sudo docker exec redroid /system/bin/pm list packages
+ grep -i konami
+ echo '=== GAME NOT INSTALLED AT ALL ==='
=== GAME NOT INSTALLED AT ALL ===
+ sudo docker exec redroid sh -c 'ls -la /data/local/tmp/splits/'
total 841768
drwxr-xr-x 2 root  root       4096 2026-09-30 00:01 .
drwxrwx--x 4 shell shell      4096 2026-09-30 00:01 ..
-rw-r--r-- 1 radio radio         2 2026-09-30 00:01 .ok
-rw-r--r-- 1 radio radio  22347497 2026-09-30 00:01 base.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 split_config.ar.apk
-rw-r--r-- 1 radio radio  57148181 2026-09-30 00:01 split_config.arm64_v8a.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 split_config.de.apk
-rw-r--r-- 1 radio radio     37074 2026-09-30 00:01 split_config.en.apk
-rw-r--r-- 1 radio radio     24786 2026-09-30 00:01 split_config.es.apk
-rw-r--r-- 1 radio radio     24786 2026-09-30 00:01 split_config.fr.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 split_config.hi.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 split_config.in.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 split_config.it.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 split_config.ja.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 split_config.ko.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 split_config.my.apk
-rw-r--r-- 1 radio radio     24786 2026-09-30 00:01 split_config.pt.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 split_config.ru.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 split_config.th.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 split_config.tr.apk
-rw-r--r-- 1 radio radio     20690 2026-09-30 00:01 split_config.vi.apk
-rw-r--r-- 1 radio radio    198371 2026-09-30 00:01 split_config.xxxhdpi.apk
-rw-r--r-- 1 radio radio     28882 2026-09-30 00:01 split_config.zh.apk
-rw-r--r-- 1 radio radio 386375435 2026-09-30 00:01 split_pad_it_0.apk
-rw-r--r-- 1 radio radio 395420368 2026-09-30 00:01 split_pad_it_1.apk
+ exit 1
```

### frida
```text
```

### logcat (filtered)
```text
```
