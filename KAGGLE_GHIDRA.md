# Ghidra on Kaggle — ready-to-run plan (faster than this VM)

Why: this VM has 2.6 GB free RAM and pages through a 160 MB binary (3–6 h,
may OOM). Kaggle CPU notebook: 4 cores, ~30 GB RAM, 12 h session cap,
20 GB persisted disk. Same analysis lands in ~30–60 min.

## 0. One-time account setup (you, 5 min)
1. https://www.kaggle.com → sign in → Account → phone-verify the account.
2. New Notebook → left panel Settings → Internet: ON. Accelerator: None (CPU).

## 1. Get libUE4.so into the notebook (pick one)
A. Upload once as a dataset: Kaggle → Datasets → New Dataset →
   upload `libUE4.so` (160,822,968 B, from `efootball-apk/native/lib/arm64-v8a/`),
   name it `libue4`. In the notebook: Add Input → your dataset
   (lands at `/kaggle/input/libue4/libUE4.so`).
B. Or re-mint the APKCombo signed URL (expires!): open the
   `.../efootball-2024/jp.konami.pesam/download/apk` page in a real browser,
   copy the `/r2?u=...` link, `curl` it inside the notebook, unzip, extract
   `config.arm64_v8a.apk` → `lib/arm64-v8a/libUE4.so`.

## 2. Notebook cells (paste in order)

Cell 1 — Java 21 + Ghidra (one-time, ~5 min on Kaggle network):
```bash
sudo apt-get update -qq && sudo apt-get install -y -qq openjdk-21-jdk-headless
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
curl -L -o ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip
echo "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db  ghidra.zip" | sha256sum -c -
unzip -q ghidra.zip
```

Cell 2 — script (paste `FindKillRule.py` from this repo's `efootball-apk/`,
but change OUT to `/kaggle/working/killrule_out.txt`).

Cell 3 — run (the long one; keep the kernel alive, ~30–60 min):
```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
mkdir -p ghidra_proj
./ghidra_12.1.4_PUBLIC/support/analyzeHeadless ghidra_proj KillRule \
  -import /kaggle/input/libue4/libUE4.so \
  -postScript FindKillRule.py -scriptPath . -deleteProject 2>&1 | tail -5
```

Cell 4 — collect:
```bash
ls -la /kaggle/working/killrule_out.txt
head -c 4000 /kaggle/working/killrule_out.txt
```
`/kaggle/working` persists + downloads: File → Download the .txt back here.

## 3. Watch-outs
- 20-min idle kill while EDITING only; a running cell keeps the session alive.
  If it dies, re-run Cell 3 (project was deleted by design; analysis restarts).
- Disk: Ghidra install ~1.5 GB + project temp several GB — inside 20 GB budget,
  but don't keep two copies of the .so.
- GPU quota irrelevant (CPU notebook, no weekly cap pressure like GPU 30 h).
- First run here died silently at ~2 h with no output; the `-analysisTimeoutPerFile 5400`
  cap from our local run is already baked into this plan if you want it — add it
  to the Cell 3 command to bound any single file to 90 min.

Expected bill: setup ~15 min + analysis 30–60 min → answers same day.
