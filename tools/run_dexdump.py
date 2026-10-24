#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_dexdump.py —— 开盘红 (com.yzj.kaipanh) 脱壳驱动 / 校验 / 修复

用法
----
  1) 自动脱壳(需要 frida + 已 root 设备 + frida-server 已运行):
       python run_dexdump.py dump --spawn
       python run_dexdump.py dump --attach            # 已手动启动 App

  2) 只校验+修复已拉回的产物:
       python run_dexdump.py verify ./kph_dump
       python run_dexdump.py verify ./kph_dump --fix  # 重算 checksum/signature

  3) 列出设备上的 dump:
       python run_dexdump.py list

依赖: pip install frida  (Python 3.7 用 frida==15.2.2)
"""
import argparse
import hashlib
import os
import struct
import subprocess
import sys
import time
import zlib

PKG = "com.yzj.kaipanh"
REMOTE_DIR = "/data/local/tmp/kph_dump"
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT_JS = os.path.join(HERE, "dexdump_360.js")


# --------------------------------------------------------------------------
# DEX 工具
# --------------------------------------------------------------------------
def dex_header_info(data):
    """返回 header dict；非 DEX 返回 None"""
    if len(data) < 0x70 or data[:4] != b"dex\n":
        return None
    (checksum,) = struct.unpack_from("<I", data, 8)
    signature = data[12:32]
    (file_size, header_size, endian_tag, link_size, link_off,
     map_off, string_ids_size, string_ids_off, type_ids_size, type_ids_off,
     proto_ids_size, proto_ids_off, field_ids_size, field_ids_off,
     method_ids_size, method_ids_off, class_defs_size, class_defs_off,
     data_size, data_off) = struct.unpack_from("<20I", data, 32)
    return {
        "version": data[4:7].decode("ascii", "replace"),
        "checksum": checksum,
        "signature": signature.hex(),
        "file_size": file_size,
        "header_size": header_size,
        "endian_tag": endian_tag,
        "map_off": map_off,
        "string_ids_size": string_ids_size,
        "string_ids_off": string_ids_off,
        "type_ids_size": type_ids_size,
        "proto_ids_size": proto_ids_size,
        "field_ids_size": field_ids_size,
        "method_ids_size": method_ids_size,
        "class_defs_size": class_defs_size,
        "class_defs_off": class_defs_off,
        "data_size": data_size,
        "data_off": data_off,
    }


def dex_validate(data, fix=False):
    """校验并可选修复。返回 (ok, msg, fixed_data_or_None)"""
    info = dex_header_info(data)
    if not info:
        return False, "not a dex (magic 不符)", None
    problems = []
    if info["header_size"] != 0x70:
        problems.append("header_size=0x%x" % info["header_size"])
    if info["endian_tag"] != 0x12345678:
        problems.append("endian_tag=0x%x" % info["endian_tag"])
    if info["file_size"] != len(data):
        problems.append("file_size=%d 实际=%d" % (info["file_size"], len(data)))
    for k in ("string_ids_off", "class_defs_off", "map_off", "data_off"):
        if info[k] >= len(data):
            problems.append("%s 越界" % k)

    # checksum / signature
    calc_sig = hashlib.sha1(data[32:]).digest()
    sig_ok = calc_sig.hex() == info["signature"]
    calc_sum = zlib.adler32(data[12:]) & 0xFFFFFFFF
    sum_ok = calc_sum == info["checksum"]

    if not sig_ok:
        problems.append("signature 不匹配(壳抹除)")
    if not sum_ok:
        problems.append("checksum 不匹配(壳抹除)")

    if not problems:
        return True, "OK  v%s  classes=%d strings=%d size=%d" % (
            info["version"], info["class_defs_size"], info["string_ids_size"], len(data)), None

    if not fix:
        return False, "; ".join(problems), None

    # 修复: 重算 signature + checksum
    buf = bytearray(data)
    if info["file_size"] != len(buf):
        struct.pack_into("<I", buf, 0x20, len(buf))
    new_sig = hashlib.sha1(bytes(buf[32:])).digest()
    buf[12:32] = new_sig
    new_sum = zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 8, new_sum)
    ok2, msg2, _ = dex_validate(bytes(buf), fix=False)
    return ok2, ("已修复 (%s) -> %s" % ("; ".join(problems), msg2)), bytes(buf)


def enumerate_strings(data, limit=40):
    """粗略取前 N 个字符串，用于人工确认是不是业务 dex"""
    info = dex_header_info(data)
    if not info:
        return []
    out = []
    n = min(info["string_ids_size"], 4000)
    for i in range(n):
        try:
            (off,) = struct.unpack_from("<I", data, info["string_ids_off"] + 4 * i)
            if off >= len(data):
                continue
            # uleb128
            p, shift, val = off, 0, 0
            while True:
                b = data[p]; p += 1
                val |= (b & 0x7F) << shift
                if b < 0x80:
                    break
                shift += 7
            end = data.index(b"\x00", p)
            s = data[p:end].decode("utf-8", "replace")
            if len(s) > 3:
                out.append(s)
        except Exception:
            continue
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------
# adb 辅助
# --------------------------------------------------------------------------
def adb(*args, **kw):
    cmd = ["adb"] + list(args)
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, **kw).decode("utf-8", "replace")
    except FileNotFoundError:
        sys.exit("[!] 找不到 adb，请把 platform-tools 加入 PATH")
    except subprocess.CalledProcessError as e:
        return e.output.decode("utf-8", "replace")


def pull_dumps(local_dir):
    os.makedirs(local_dir, exist_ok=True)
    adb("shell", "mkdir", "-p", REMOTE_DIR)
    out = adb("pull", REMOTE_DIR, local_dir)
    print(out.strip())
    # adb pull 会把目录放到 local_dir/kph_dump 下
    cand = os.path.join(local_dir, "kph_dump")
    return cand if os.path.isdir(cand) else local_dir


# --------------------------------------------------------------------------
# 命令实现
# --------------------------------------------------------------------------
def cmd_dump(args):
    try:
        import frida
    except ImportError:
        sys.exit("[!] 未安装 frida。执行: pip install frida==15.2.2  (Py3.7)\n"
                 "    或  pip install frida            (Py3.8+)")

    with open(SCRIPT_JS, "r", encoding="utf-8") as f:
        js = f.read()

    dev = frida.get_usb_device(timeout=10)
    print("[*] 设备: %s" % dev)

    if args.spawn:
        pid = dev.spawn([PKG])
        print("[*] spawn pid=%d" % pid)
        session = dev.attach(pid)
        dev.resume(pid)
    else:
        session = dev.attach(PKG)
        print("[*] attach 到已运行进程")

    script = session.create_script(js)
    script.on("message", lambda m, d: print("[js] %s" % (m.get("payload") or m)))
    script.load()
    print("[*] 脚本已注入，等待 %d 秒完成扫描..." % args.wait)
    time.sleep(args.wait)

    try:
        script.unload()
    except Exception:
        pass
    session.detach()

    print("[*] 拉取产物")
    outdir = pull_dumps(args.out)
    print("[*] 产物目录: %s" % outdir)
    do_verify_dir(outdir, fix=True, quiet=False)


def cmd_list(args):
    print(adb("shell", "ls", "-l", REMOTE_DIR))


def do_verify_dir(path, fix=False, quiet=False):
    if not os.path.isdir(path):
        sys.exit("[!] 不是目录: %s" % path)
    files = sorted(f for f in os.listdir(path)
                   if f.endswith(".dex") or f.endswith(".part.dex"))
    if not files:
        print("[!] %s 下没有 .dex" % path)
        return
    good = 0
    for fn in files:
        fp = os.path.join(path, fn)
        data = open(fp, "rb").read()
        ok, msg, fixed = dex_validate(data, fix=fix)
        tag = "OK  " if ok else "BAD "
        print("%s %-28s %8d  %s" % (tag, fn, len(data), msg))
        if ok:
            good += 1
            if not quiet:
                strs = enumerate_strings(data, 12)
                print("      strings: %s" % " | ".join(s[:32] for s in strs[:12]))
        if fixed:
            outfp = fp.replace(".part.dex", ".fixed.dex").replace(".dex", ".fixed.dex")
            if outfp == fp:
                outfp = fp + ".fixed.dex"
            open(outfp, "wb").write(fixed)
            print("      -> 已写出修复版 %s" % outfp)
    print("\n[=] 共 %d 个文件, %d 个可用" % (len(files), good))


def cmd_verify(args):
    do_verify_dir(args.path, fix=args.fix, quiet=False)


def main():
    ap = argparse.ArgumentParser(description="开盘红 360加固 脱壳驱动/校验")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("dump", help="frida 脱壳")
    p1.add_argument("--spawn", action="store_true", help="spawn 方式启动(推荐)")
    p1.add_argument("--attach", action="store_true", help="attach 已运行进程")
    p1.add_argument("--wait", type=int, default=25, help="注入后等待秒数")
    p1.add_argument("--out", default="./kph_dump", help="本地输出目录")
    p1.set_defaults(func=cmd_dump)

    p2 = sub.add_parser("verify", help="校验/修复 dump")
    p2.add_argument("path")
    p2.add_argument("--fix", action="store_true", help="重算 checksum/signature")
    p2.set_defaults(func=cmd_verify)

    p3 = sub.add_parser("list", help="列出设备上的 dump")
    p3.set_defaults(func=cmd_list)

    args = ap.parse_args()
    if args.cmd == "dump" and not (args.spawn or args.attach):
        args.spawn = True
    args.func(args)


if __name__ == "__main__":
    main()
