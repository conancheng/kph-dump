#!/usr/bin/env bash
# ============================================================================
# dump.sh —— 在 GitHub Actions 的 emulator 里执行
#
# 关键: reactivecircus/android-emulator-runner 会把 workflow 里的 script
#       字段按行拆开, 每行一个 /usr/bin/sh -c 执行。
#       所以多行 if/while/变量赋值必须放进独立文件, workflow 里只写:
#           script: bash tools/dump.sh
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
df -h /
ls -l /dev/kvm 2>&1

echo "########## ADB ##########"
adb version
adb devices -l
adb wait-for-device
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.kernel.qemu

echo "########## ROOT ##########"
adb root 2>&1
sleep 5
adb wait-for-device
adb shell id

echo "########## INSTALL ##########"
echo "APK=$APK"
ls -l "$APK"
adb install -r -t "$APK" 2>&1 | tee diag/install.log
adb shell pm list packages 2>&1 | grep -i kaipanh
adb shell dumpsys package "$PKG" 2>&1 | grep -E 'versionName|codePath|primaryCpuAbi'

echo "########## FRIDA SERVER ##########"
if [ -f /tmp/fs ]; then
    adb push /tmp/fs /data/local/tmp/frida-server 2>&1
    adb shell "chmod 755 /data/local/tmp/frida-server"
    adb shell "nohup /data/local/tmp/frida-server -D >/dev/null 2>&1 &"
    sleep 6
    adb shell "ps -A | grep -i frida"
else
    echo "NO_FRIDA_SERVER (继续走 /proc 方案)"
fi

echo "########## LAUNCH APP ##########"
adb shell am start -W -n "$PKG/.splash.SplashActivity" 2>&1
sleep 30
adb shell "ps -A | grep -i kaipanh"
PID=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')
echo "PID=$PID"

if [ -n "$PID" ]; then
    adb shell "cat /proc/$PID/maps" > dump3/maps.txt 2>&1
    echo "--- dex/dalvik mappings ---"
    grep -iE 'dex|dalvik' dump3/maps.txt | head -40
    echo "--- total mappings ---"
    wc -l dump3/maps.txt
fi

echo "########## DUMP A: frida-dexdump ##########"
if command -v frida-dexdump >/dev/null 2>&1; then
    frida-dexdump -U -f "$PKG" -d 12 -o ./dump 2>&1 | tail -50
else
    echo "NO_FRIDA_DEXDUMP"
fi
ls -laR ./dump 2>&1 | head -40

echo "########## DUMP B: custom js (dexdump_360.js) ##########"
if command -v frida >/dev/null 2>&1; then
    adb shell "rm -rf /data/local/tmp/kph_dump; mkdir -p /data/local/tmp/kph_dump"
    timeout 180 frida -U -f "$PKG" -l tools/dexdump_360.js --no-pause 2>&1 | tail -60
    sleep 45
    adb pull /data/local/tmp/kph_dump ./dump2 2>&1 | tail -5
else
    echo "NO_FRIDA_CLI"
fi
ls -laR ./dump2 2>&1 | head -40

echo "########## DUMP C: /proc/pid/mem ##########"
PID=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')
echo "PID=$PID"
if [ -n "$PID" ]; then
    adb shell "cat /proc/$PID/maps" > dump3/maps.txt 2>&1
    grep -iE 'dex|dalvik' dump3/maps.txt | awk '{print $1}' > dump3/ranges.txt 2>&1
    echo "ranges: $(wc -l < dump3/ranges.txt)"
    adb shell "rm -f /data/local/tmp/seg_*.bin"
    n=0
    while read -r rng; do
        [ -z "$rng" ] && continue
        S=${rng%%-*}
        E=${rng##*-}
        SO=$((16#$S))
        EO=$((16#$E))
        SZ=$((EO-SO))
        [ "$SZ" -le 0 ] && continue
        [ "$SZ" -gt 67108864 ] && continue
        n=$((n+1))
        adb shell "dd if=/proc/$PID/mem of=/data/local/tmp/seg_${SO}.bin bs=4096 skip=$((SO/4096)) count=$((SZ/4096)) 2>/dev/null"
    done < dump3/ranges.txt
    echo "dumped_segments=$n"
    adb pull /data/local/tmp ./dump3/raw 2>&1 | tail -5
else
    echo "NO_PID"
fi

echo "########## LOGCAT ##########"
adb logcat -d -t 800 > dump3/logcat.txt 2>&1
echo "--- logcat 里与加固/frida 相关的行 ---"
grep -iE 'jiagu|stub|frida|tinker|emulator|detect|root' dump3/logcat.txt | head -40
tail -60 dump3/logcat.txt

echo "########## SUMMARY ##########"
find dump dump2 dump3 -type f 2>/dev/null | head -80
du -sh dump dump2 dump3 2>/dev/null
echo ALL_DONE
exit 0
