# kph-dump

开盘红 (com.yzj.kaipanh) v6.0.10 脱壳工作区。

- .github/workflows/dump-kph.yml — 在 GitHub Actions 的 KVM 上跑 x86_64 模拟器并 dump dex
- $(D:\deepseek\开盘红\kph_6.0.10.apk.Name) — 待分析样本
- 	ools/ — 脱壳脚本

## 触发

Actions → dump-kph → Run workflow

## 产物

artifact dexdump，含 dump/（frida-dexdump）、dump2/（自定义内存扫描）、dump3/（/proc/pid/mem 兜底 + logcat）。
