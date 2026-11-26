# eFootball update guest

Use the **efootball-update** mode of the **Owner native ARM64 kickoff lab** workflow
when you need to collect the current official eFootball data. It boots the
verified 11.1.1 installation in a dedicated guest at `127.0.0.1:15557`.

```sh
gh workflow run kgs-capture.yml -R EdenAlpha/peerlink-efootball-disconnects \
  --ref research/celebration-offline-20261124 -f mode=efootball-update
```

GitHub restores the six signed APK splits and the ten asset packs from the
checksum-verified cache. A cache miss is rebuilt from the version-pinned APK
bundle and the `game-full-20261012` backup. Use **cache-only** to populate the
cache without starting a phone.

Complete the game's first-launch prompts on a fresh guest and choose
**Download** at **Download Latest Data?**. Opening the same guest again
within its run preserves setup. A new GitHub run starts a fresh Android
guest. The cache contains the static installation files only.

In update mode, use the run-specific owner transport branches
`live-cmd-efootball-update-<run-id>` and `live-res-efootball-update-<run-id>`.

After the live update finishes, the game's data archive is at
`/data/user/0/jp.konami.pesam/files/Download/dt870_mobile_and.cpk`.
Record its exact byte count and SHA-256 before using it with PeerLink.
