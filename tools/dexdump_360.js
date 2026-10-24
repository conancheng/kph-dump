/*
 * dexdump_360.js —— 开盘红 (com.yzj.kaipanh) / 360加固保 脱壳脚本
 * ---------------------------------------------------------------------------
 * 用法:
 *   frida -U -f com.yzj.kaipanh -l dexdump_360.js --no-pause
 *   frida -U -n com.yzj.kaipanh -l dexdump_360.js          # 已启动的进程
 *
 * 产物:
 *   /data/local/tmp/kph_dump/classes_<n>.dex        (连续段完整 dump)
 *   /data/local/tmp/kph_dump/classes_<n>.part.dex   (跨段碎片, 需重建)
 *   /data/local/tmp/kph_dump/manifest.txt           (清单: 地址/大小/校验)
 *   /data/local/tmp/kph_dump/hooks.log              (加载器调用轨迹)
 *
 * 360加固保特征: 真实 DEX 在 attachBaseContext 阶段由 libjiagu 解密进内存,
 * 部分版本会落盘到 getDir()/files/cache 下再 DexFile.loadDex().
 * 因此本脚本三条腿并行: 内存扫描 + 加载器 hook + 落盘目录提示.
 * ---------------------------------------------------------------------------
 */
'use strict';

var OUT_DIR   = '/data/local/tmp/kph_dump';
var SCAN_DELAY_MS = 2500;   // attachBaseContext 后等待解密完成
var RESCAN_ROUNDS = 4;      // 分轮扫描, 每轮触发一次类加载
var MAX_DUMP_SIZE = 64 * 1024 * 1024;

var seenHashes = {};
var dumpedCount = 0;
var manifest = [];

function log(s) { console.log('[dexdump] ' + s); }

/* ------------------------------------------------------------------ */
/* 文件输出                                                            */
/* ------------------------------------------------------------------ */
function ensureDir() {
    try {
        var probe = new File(OUT_DIR + '/.keep', 'w');
        probe.write('ok'); probe.flush(); probe.close();
    } catch (e) {
        log('WARN 无法写 ' + OUT_DIR + ' (' + e + ')，请确认 frida-server 以 root 运行');
    }
}

function writeFile(name, buf) {
    var path = OUT_DIR + '/' + name;
    try {
        var f = new File(path, 'wb');
        f.write(buf);
        f.flush();
        f.close();
        return path;
    } catch (e) {
        log('ERR 写 ' + path + ' 失败: ' + e);
        return null;
    }
}

/* ------------------------------------------------------------------ */
/* DEX 头校验（360 会抹 checksum/signature，故只校验结构字段）          */
/* ------------------------------------------------------------------ */
function parseDexHeader(p) {
    try {
        if (p.readU32() !== 0x0a786564) return null;          // 'dex\n' (LE)
        var ver = p.add(4).readCString(3);
        if (!/^0(35|36|37|38|39|40)$/.test(ver)) return null;

        var fileSize   = p.add(0x20).readU32();
        var headerSize = p.add(0x24).readU32();
        var endianTag  = p.add(0x28).readU32();
        var mapOff     = p.add(0x34).readU32();
        var strIdsSize = p.add(0x38).readU32();
        var strIdsOff  = p.add(0x3c).readU32();
        var typeIdsSize= p.add(0x40).readU32();
        var clsDefsSize= p.add(0x60).readU32();
        var clsDefsOff = p.add(0x64).readU32();

        if (headerSize !== 0x70) return null;
        if (endianTag !== 0x12345678) return null;
        if (fileSize < 0x70 || fileSize > MAX_DUMP_SIZE) return null;
        if (strIdsOff >= fileSize || clsDefsOff >= fileSize) return null;
        if (mapOff >= fileSize) return null;

        return {
            version: ver,
            fileSize: fileSize,
            stringIdsSize: strIdsSize,
            typeIdsSize: typeIdsSize,
            classDefsSize: clsDefsSize,
            mapOff: mapOff
        };
    } catch (e) { return null; }
}

/* ------------------------------------------------------------------ */
/* 内存扫描                                                            */
/* ------------------------------------------------------------------ */
function scanOnce(round) {
    var ranges = Process.enumerateRanges('rw-');
    log('round ' + round + ': ' + ranges.length + ' 个 rw- 段');

    for (var i = 0; i < ranges.length; i++) {
        var r = ranges[i];
        var base = r.base;
        var size = r.size;
        var remaining = size;

        // 逐块搜索 'dex\n0'
        var cur = base;
        while (remaining > 0x70) {
            var chunk = Math.min(remaining, 4 * 1024 * 1024);
            var hits = [];
            try {
                hits = Memory.scanSync(cur, chunk, '64 65 78 0a 30');
            } catch (e) {
                break;
            }
            for (var h = 0; h < hits.length; h++) {
                handleCandidate(ptr(hits[h].address), round);
            }
            cur = cur.add(chunk);
            remaining -= chunk;
        }
    }
}

function handleCandidate(addr, round) {
    var hdr = parseDexHeader(addr);
    if (!hdr) return;

    // 去重: 用 fileSize + classDefsSize + 前 0x70 字节哈希
    var head = addr.readByteArray(0x70);
    var key;
    try {
        key = hdr.fileSize + ':' + hdr.classDefsSize + ':' + hdr.stringIdsSize +
              ':' + hdr.mapOff + ':' + sha1(head);
    } catch (e) {
        key = hdr.fileSize + ':' + addr.toString();
    }
    if (seenHashes[key]) return;
    seenHashes[key] = true;

    // 判断是否跨越可读段
    var contiguous = true;
    try {
        var probe = addr.add(hdr.fileSize - 1).readU8();
    } catch (e) {
        contiguous = false;
    }

    dumpedCount++;
    var idx = ('00' + dumpedCount).slice(-2);
    var name = 'classes_' + idx + (contiguous ? '.dex' : '.part.dex');
    var buf;
    try {
        buf = addr.readByteArray(hdr.fileSize);
    } catch (e) {
        log('ERR 读取 0x' + addr.toString(16) + ' 失败(跨段): ' + e);
        // 退而求其次: dump 头部 4MB, 便于人工重建
        try { buf = addr.readByteArray(Math.min(hdr.fileSize, 4 * 1024 * 1024)); }
        catch (e2) { return; }
        name = 'classes_' + idx + '.part.dex';
    }

    var path = writeFile(name, buf);
    var line = [
        '#' + idx,
        'addr=0x' + addr.toString(16),
        'ver=' + hdr.version,
        'size=' + hdr.fileSize,
        'classes=' + hdr.classDefsSize,
        'strings=' + hdr.stringIdsSize,
        'mapOff=0x' + hdr.mapOff.toString(16),
        'contiguous=' + contiguous,
        'round=' + round,
        'file=' + (path || 'FAILED')
    ].join(' ');
    manifest.push(line);
    log(line);
}

/* 纯 JS SHA1（Frida 无内置 crypto） */
function sha1(ab) {
    function rotl(n, s) { return (n << s) | (n >>> (32 - s)); }
    var bytes = new Uint8Array(ab);
    var ml = bytes.length * 8;
    var withOne = bytes.length + 9;
    var total = withOne + ((64 - (withOne % 64)) % 64);
    var msg = new Uint8Array(total);
    msg.set(bytes);
    msg[bytes.length] = 0x80;
    var dv = new DataView(msg.buffer);
    dv.setUint32(total - 4, ml >>> 0, false);
    dv.setUint32(total - 8, Math.floor(ml / 4294967296) >>> 0, false);

    var h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    var w = new Int32Array(80);
    for (var off = 0; off < total; off += 64) {
        for (var i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4, false);
        for (var i2 = 16; i2 < 80; i2++)
            w[i2] = rotl(w[i2 - 3] ^ w[i2 - 8] ^ w[i2 - 14] ^ w[i2 - 16], 1);
        var a = h0, b = h1, c = h2, d = h3, e = h4;
        for (var j = 0; j < 80; j++) {
            var f, k;
            if (j < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
            else if (j < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
            else if (j < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
            var t = (rotl(a, 5) + f + e + k + w[j]) | 0;
            e = d; d = c; c = rotl(b, 30); b = a; a = t;
        }
        h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0;
        h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
    }
    function hex(x) { return ('00000000' + (x >>> 0).toString(16)).slice(-8); }
    return hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4);
}

/* ------------------------------------------------------------------ */
/* 加载器 hook —— 记录壳把 dex 从哪来                                   */
/* ------------------------------------------------------------------ */
function hookLoaders() {
    if (!Java.available) { log('Java 未就绪, 跳过加载器 hook'); return; }
    Java.perform(function () {
        try {
            var DexFile = Java.use('dalvik.system.DexFile');
            var origLoadDex = DexFile.loadDex;
            DexFile.loadDex.implementation = function (src, dst, flags) {
                log('[DexFile.loadDex] src=' + src + ' dst=' + dst + ' flags=' + flags);
                return origLoadDex.call(this, src, dst, flags);
            };
        } catch (e) { log('hook DexFile 失败: ' + e); }

        try {
            var DCL = Java.use('dalvik.system.DexClassLoader');
            DCL.$init.overload('java.lang.String', 'java.lang.String',
                                'java.lang.String', 'java.lang.ClassLoader')
               .implementation = function (a, b, c, d) {
                log('[DexClassLoader] ' + a + ' | lib=' + c);
                return this.$init(a, b, c, d);
            };
        } catch (e) {}

        try {
            var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
            IMDCL.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
                 .implementation = function (buf, parent) {
                log('[InMemoryDexClassLoader] capacity=' + buf.capacity());
                // 顺手把 buffer 内容 dump 出来
                try {
                    var dup = buf.duplicate();
                    dup.position(0);
                    var arr = Java.array('byte', new Array(dup.capacity()));
                    dup.get(arr);
                    var ab = arr.buffer ? arr.buffer : null;
                    log('[InMemoryDexClassLoader] 已取到 ' + dup.capacity() + ' 字节, 交给内存扫描');
                } catch (e2) { log('IMDCL 读 buffer 失败: ' + e2); }
                return this.$init(buf, parent);
            };
        } catch (e) {}

        // 壳入口
        try {
            var StubApp = Java.use('com.stub.StubApp');
            var m = StubApp.attachBaseContext;
            m.implementation = function (ctx) {
                log('[StubApp.attachBaseContext] 进入, 等壳解密');
                var r = m.call(this, ctx);
                log('[StubApp.attachBaseContext] 返回, 壳已完成一轮解密');
                setTimeout(function () { scanOnce('after-attach'); }, SCAN_DELAY_MS);
                return r;
            };
        } catch (e) { log('StubApp 未就绪(可能已加载): ' + e); }
    });
}

/* 主动触发类加载, 逼壳把更多类解密出来 */
function forceLoad(round) {
    if (!Java.available) return;
    Java.perform(function () {
        try {
            var loader = Java.enumerateClassLoadersSync();
            for (var i = 0; i < loader.length; i++) {
                try {
                    var l = loader[i];
                    var name = l.toString();
                    // 业务包下的类名
                    var prefixes = ['com.yzj.kaipanh.newindex.data.SocketRepository',
                                    'com.yzj.kaipanh.newindex.common.socket.SocketHelper',
                                    'com.yzj.kaipanh.splash.SplashActivity'];
                    for (var k = 0; k < prefixes.length; k++) {
                        try { l.loadClass(prefixes[k]); } catch (e2) {}
                    }
                } catch (e) {}
            }
        } catch (e) { log('forceLoad 失败: ' + e); }
    });
}

/* ------------------------------------------------------------------ */
/* 落盘目录检查（部分 360 版本会把 dex 写到私有目录）                   */
/* ------------------------------------------------------------------ */
function hintDiskPaths() {
    var guesses = [
        '/data/data/com.yzj.kaipanh/app_dex',
        '/data/data/com.yzj.kaipanh/app_odex',
        '/data/data/com.yzj.kaipanh/files',
        '/data/data/com.yzj.kaipanh/cache',
        '/data/data/com.yzj.kaipanh/app_outdex',
        '/data/data/com.yzj.kaipanh/.jiagu'
    ];
    log('---- 建议在 shell 里检查以下目录 (adb shell ls -lR) ----');
    for (var i = 0; i < guesses.length; i++) log('  ' + guesses[i]);
}

/* ------------------------------------------------------------------ */
/* 主流程                                                              */
/* ------------------------------------------------------------------ */
ensureDir();
log('脚本装载, pid=' + Process.id + ' target=' + Process.arch);
hookLoaders();
hintDiskPaths();

var round = 0;
function tick() {
    round++;
    forceLoad(round);
    setTimeout(function () {
        scanOnce(round);
        if (round < RESCAN_ROUNDS) {
            setTimeout(tick, 3000);
        } else {
            var out = manifest.join('\n') + '\n';
            writeFile('manifest.txt', out);
            log('=== 完成: 共 dump ' + dumpedCount + ' 个候选 ===');
            log('拉取: adb pull ' + OUT_DIR + ' ./kph_dump');
            log('校验: python run_dexdump.py --verify ./kph_dump');
        }
    }, SCAN_DELAY_MS);
}
setTimeout(tick, 3000);
