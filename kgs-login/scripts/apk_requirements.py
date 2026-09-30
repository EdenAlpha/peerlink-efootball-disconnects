"""Extract the install-time requirements an APK declares.

Play's "not compatible with this device" verdict is computed from exactly these
declarations: minSdkVersion, uses-sdk, uses-feature (with required flag),
uses-native-library, and the GLES version request. This prints them so a
device can be diffed against them without guessing.

Usage: python apk_requirements.py <path-to.apk>
"""
from __future__ import annotations

import sys

from androguard.core.apk import APK


NS = "{http://schemas.android.com/apk/res/android}"


def android(el, attr: str):
    """Read an android:-namespaced attribute off an ElementTree element."""
    return el.get(NS + attr)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    apk = APK(sys.argv[1])

    print(f"package       : {apk.get_package()}")
    print(f"versionName   : {apk.get_androidversion_name()}")
    print(f"versionCode   : {apk.get_androidversion_code()}")
    print(f"minSdkVersion : {apk.get_min_sdk_version()}")
    print(f"targetSdk     : {apk.get_target_sdk_version()}")
    print(f"maxSdkVersion : {apk.get_max_sdk_version()}")

    xml = apk.get_android_manifest_xml()

    print("\nuses-feature (name | required | version):")
    for el in xml.iter("uses-feature"):
        name = android(el, "name") or ""
        req = android(el, "required")
        ver = android(el, "version")
        gles = android(el, "glEsVersion")
        bits = [f"required={req if req is not None else 'unset'}"]
        if ver:
            bits.append(f"version={ver}")
        if gles:
            bits.append(f"glEsVersion={gles}")
        if name.startswith(("android.hardware.opengles", "android.hardware.vulkan")):
            bits.append("<== GRAPHICS REQUIREMENT")
        print(f"  {name:52s} {' '.join(bits)}")

    print("\nuses-native-library (name | required):")
    for el in xml.iter("uses-native-library"):
        print(f"  {android(el, 'name'):52s} required={android(el, 'required')}")

    print("\nsupports-screens:")
    for el in xml.iter("supports-screens"):
        print("  " + " ".join(f"{k.split('}')[-1]}={v}" for k, v in el.attrib.items()))

    print("\ndeclared permissions of interest:")
    wanted = ("VIBRATE", "WAKE_LOCK", "INTERNET", "FOREGROUND_SERVICE",
              "QUERY_ALL_PACKAGES", "REQUEST_INSTALL_PACKAGES",
              "MANAGE_EXTERNAL_STORAGE", "PACKAGE_USAGE_STATS")
    granted = apk.get_permissions() or []
    for p in wanted:
        if "android.permission." + p in granted:
            print(f"  android.permission.{p}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())