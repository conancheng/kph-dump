#!/usr/bin/env bash
# ============================================================================
# dump.sh v2 —— 在 GitHub Actions 的 emulator 里执行
#
# 约束: reactivecircus/android-emulator-runner 会把 workflow 的 script 字段
#       按行拆开, 每行一个 /usr/bin/sh -c 执行。多行逻辑必须放独立文件。
#
# v2 修复 (v1 实测暴露的三个 bug):
#   1. frida-dexdump 的 -d 是 debug 布尔开关, 不是 delay —— 去掉 `-d 12`,
#      否则 "12" 会被并进 -f 的值, 报 argv not supported。
#   2. 新版 frida CLI 已移除 --no-pause —— 去掉。
#   3. while read 循环里调 adb shell, adb 会吞掉剩余 stdin, 循环只跑一次
#      —— 每条 adb 调用加 `< /dev/null`。
#
# 目标段 (实测已在内存中):
#   [anon:dalvik-classes.dex extracted in memory from .../base.apk]  ≈ 17 MB
# ============================================================================
set +e

PKG="com.yzj.kaipanh"
APK="${APK:-$(find . -maxdepth 2 -name 'kph_*.apk' | head -1)}"

mkdir -p diag dump dump2 dump3
exec > >(tee -a diag/script.log) 2>&1

echo "########## ENV ##########"
date -u
uname -a
nproc
free -m
ls -l /dev/kvm 2>&1

echo "########## ADB / ROOT ##########"
adb wait-for-device
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.cpu.abi
adb root 2>&1
sleep 5
adb wait-for-device
adb shell id

echo "########## INSTALL ##########"
echo "APK=$APK"
adb install -r -t "$APK" 2>&1 | tee diag/install.log
adb shell pm list packages 2>&1 | grep -i kaipanh
adb shell dumpsys package "$PKG" 2>&1 | grep -E 'versionName|primaryCpuAbi'

echo "########## FRIDA SERVER ##########"
if [ -f /tmp/fs ]; then
    adb push /tmp/fs /data/local/tmp/frida-server 2>&1
    adb shell "chmod 755 /data/local/tmp/frida-server" < /dev/null
    adb shell "nohup /data/local/tmp/frida-server -D >/dev/null 2>&1 &" < /dev/null
    sleep 6
    adb shell "ps -A | grep -i frida" < /dev/null
else
    echo "NO_FRIDA_SERVER"
fi

echo "########## LAUNCH APP ##########"
adb shell am start -W -n "$PKG/.splash.SplashActivity" < /dev/null 2>&1
sleep 35
adb shell "ps -A | grep -i kaipanh" < /dev/null
PID=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')
echo "PID=$PID"

echo "########## MAPS ##########"
if [ -n "$PID" ]; then
    adb shell "cat /proc/$PID/maps" < /dev/null > dump3/maps.txt 2>&1
    wc -l dump3/maps.txt
    echo "--- 目标 dex 段 ---"
    grep -iE 'dalvik-classes\.dex|extracted in memory' dump3/maps.txt
    echo "--- vdex ---"
    grep -iE '\.vdex' dump3/maps.txt | head -10
    echo "--- jiagu ---"
    grep -iE 'jiagu' dump3/maps.txt
fi

# --------------------------------------------------------------------------
# DUMP A: /proc/pid/mem 直读（最可靠，不依赖 frida）
# --------------------------------------------------------------------------
echo "########## DUMP A: /proc/pid/mem ##########"
PID=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')
if [ -n "$PID" ]; then
    adb shell "cat /proc/$PID/maps" < /dev/null > dump3/maps.txt 2>&1
    # 只挑真正装着 dex 的段: dalvik-classes.dex / 内存中解出的 dex / vdex
    grep -iE 'dalvik-classes\.dex|extracted in memory|\.vdex' dump3/maps.txt \
        | awk '{print $1}' > dump3/ranges.txt 2>&1
    echo "target ranges: $(wc -l < dump3/ranges.txt)"
    cat dump3/ranges.txt

    adb shell "rm -rf /data/local/tmp/seg_*.bin" < /dev/null
    n=0
    while read -r rng; do
        [ -z "$rng" ] && continue
        S=${rng%%-*}
        E=${rng##*-}
        SO=$((16#$S))
        EO=$((16#$E))
        SZ=$((EO-SO))
        [ "$SZ" -le 0 ] && continue
        [ "$SZ" -gt 134217728 ] && continue
        n=$((n+1))
        echo ">>> seg $n: $rng  size=$SZ"
        # 关键: < /dev/null 防止 adb 吞掉 while 的 stdin
        adb shell "dd if=/proc/$PID/mem of=/data/local/tmp/seg_${SO}.bin bs=4096 skip=$((SO/4096)) count=$((SZ/4096)) 2>/dev/null" < /dev/null
        adb shell "ls -l /data/local/tmp/seg_${SO}.bin" < /dev/null
    done < dump3/ranges.txt
    echo "dumped_segments=$n"
    adb pull /data/local/tmp ./dump3/raw 2>&1 | tail -8
else
    echo "NO_PID"
fi

# --------------------------------------------------------------------------
# DUMP B: frida-dexdump（修正参数后）
# --------------------------------------------------------------------------
echo "########## DUMP B: frida-dexdump ##########"
if command -v frida-dexdump >/dev/null 2>&1; then
    adb shell "am force-stop $PKG" < /dev/null 2>&1
    sleep 2
    # 注意: -d 是 debug 开关; 不加 delay 参数; -o 指定输出目录
    timeout 240 frida-dexdump -U -f "$PKG" -o ./dump 2>&1 | tail -60
else
    echo "NO_FRIDA_DEXDUMP"
fi
ls -laR ./dump 2>&1 | head -40

# --------------------------------------------------------------------------
# DUMP C: 自定义 js（去掉 --no-pause）
# --------------------------------------------------------------------------
echo "########## DUMP C: custom js ##########"
if command -v frida >/dev/null 2>&1; then
    adb shell "am force-stop $PKG" < /dev/null 2>&1
    sleep 2
    adb shell "rm -rf /data/local/tmp/kph_dump; mkdir -p /data/local/tmp/kph_dump" < /dev/null
    timeout 200 frida -U -f "$PKG" -l tools/dexdump_360.js 2>&1 | tail -60
    sleep 40
    adb pull /data/local/tmp/kph_dump ./dump2 2>&1 | tail -5
else
    echo "NO_FRIDA_CLI"
fi
ls -laR ./dump2 2>&1 | head -40

echo "########## LOGCAT ##########"
adb logcat -d -t 1000 > dump3/logcat.txt 2>&1
echo "--- 加固/检测相关 ---"
grep -iE 'jiagu|stub|tinker|frida|detect|emulator|root|xposed' dump3/logcat.txt | head -40
tail -60 dump3/logcat.txt

echo "########## SUMMARY ##########"
find dump dump2 dump3 -type f 2>/dev/null | head -80
du -sh dump dump2 dump3 2>/dev/null
echo ALL_DONE
exit 0
