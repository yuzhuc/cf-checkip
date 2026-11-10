import subprocess, re, time, socket, sys, os
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- 平台检测 ----------
IS_WIN   = (os.name == 'nt')
IS_MAC   = (sys.platform == 'darwin')
IS_LINUX = (not IS_WIN and not IS_MAC)

if not (IS_WIN or IS_MAC or IS_LINUX):
    print(f"[ERR] 不支持的平台: {sys.platform}", file=sys.stderr)
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

INPUT_FILE        = os.path.join(BASE_DIR, "cf-v6.txt")
OUT_ALL           = os.path.join(BASE_DIR, "all_ok.txt")
OUT_SORT_PING     = os.path.join(BASE_DIR, "sorted_ping.txt")
OUT_SORT_TCPING   = os.path.join(BASE_DIR, "sorted_tcping.txt")
OUT_RANGE_0_100   = os.path.join(BASE_DIR, "range_0_100.txt")
OUT_RANGE_100_200 = os.path.join(BASE_DIR, "range_100_200.txt")
OUT_CHECK         = os.path.join(BASE_DIR, "check-v6.txt")
OUT_HISTORY       = os.path.join(BASE_DIR, "checkip.log")

DEFAULT_X        = 25
MIN_RANGE_0_100  = 10
PING_TIMEOUT_MS  = 1000
PING_RETRY       = 1
TCP_TIMEOUT      = 1.0
TCP_RETRY        = 1
TCP_PORT         = 443
MAX_WORKERS      = 250

# IPv6 最长 39 字符（8 段 ×4 hex + 7 个 ':'），预留一点
COL_IP, COL_P, COL_T = 44, 8, 8

# ---------- ping 命令（按平台，IPv6） ----------
if IS_WIN:
    PING_CMD_PREFIX = ["ping", "-6", "-n", "1", "-w", str(PING_TIMEOUT_MS)]
    PING_ENCODING   = "mbcs"
    SUBPROCESS_KW   = {"creationflags": 0x08000000}
elif IS_MAC:
    # macOS 的 ping6 对非 loopback 不认 -W，靠 subprocess timeout 兜底
    PING_CMD_PREFIX = ["ping6", "-c", "1"]
    PING_ENCODING   = "utf-8"
    SUBPROCESS_KW   = {}
else:  # Linux
    _linux_wait     = max(1, PING_TIMEOUT_MS // 1000)
    PING_CMD_PREFIX = ["ping", "-6", "-c", "1", "-W", str(_linux_wait)]
    PING_ENCODING   = "utf-8"
    SUBPROCESS_KW   = {}

# 与 IPv4 一致：time=12.3 ms / time<1ms
PING_RE = re.compile(r'([=<])\s*(\d+(?:\.\d+)?)\s*ms', re.IGNORECASE)

WRITE_FAILS = []


def _is_valid_ipv6_placeholder(s: str) -> bool:
    """支持完整 IPv6，以及末尾 :x 占位符（把 :x 换成 :0 再校验）"""
    s = s.strip()
    if not s:
        return False
    if s.lower().endswith(':x'):
        try:
            ipaddress.IPv6Address(s[:-1] + '0')
            return True
        except ValueError:
            return False
    try:
        ipaddress.IPv6Address(s)
        return True
    except ValueError:
        return False


def resolve_ip(placeholder: str, x: int) -> str:
    """把末尾 :x 替换成 x 的十六进制；其余原样返回"""
    ph = placeholder.strip()
    idx = ph.rfind(':')
    if idx >= 0 and ph[idx + 1:].lower() == 'x':
        return ph[:idx + 1] + format(x, 'x')
    return ph


def ip_sort_key(ip: str) -> int:
    ip = ip.strip()
    if ip.lower().endswith(':x'):
        ip = ip[:-1] + '0'
    try:
        return int(ipaddress.IPv6Address(ip))
    except ValueError:
        return 0


def _parse_ping_ms(stdout: str):
    m = PING_RE.search(stdout)
    if not m:
        return None
    sign, num = m.group(1), float(m.group(2))
    return 0 if sign == '<' else int(round(num))


def ping_one(ip, retries=PING_RETRY):
    for _ in range(1 + retries):
        try:
            r = subprocess.run(
                PING_CMD_PREFIX + [ip],
                capture_output=True, text=True, encoding=PING_ENCODING,
                errors="ignore",
                timeout=PING_TIMEOUT_MS / 1000 + 0.5,
                **SUBPROCESS_KW,
            )
            v = _parse_ping_ms(r.stdout or "")
            if v is not None:
                return v
        except Exception:
            pass
    return None


def tcping_one(ip, port=TCP_PORT, timeout=TCP_TIMEOUT, retries=TCP_RETRY):
    for _ in range(1 + retries):
        s = None
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(timeout)
            t0 = time.perf_counter()
            # IPv6 的 connect 需要 4 元组 (host, port, flowinfo, scope_id)
            s.connect((ip, port, 0, 0))
            return int(round((time.perf_counter() - t0) * 1000))
        except Exception:
            pass
        finally:
            if s:
                try: s.close()
                except Exception: pass
    return None


def test_one(placeholder, x):
    real = resolve_ip(placeholder, x)
    return placeholder, ping_one(real), tcping_one(real)


def fmt_cell(v, width):
    s = "-" if v is None else str(v)
    return f"{s:>{width}}"


def fmt_row(ip, p, t):
    return f"{ip:<{COL_IP}}{fmt_cell(p, COL_P)}{fmt_cell(t, COL_T)}"


def fmt_header():
    return f"{'IP':<{COL_IP}}{'ping':>{COL_P}}{'tcp':>{COL_T}}"


def fmt_sep():
    return "-" * (COL_IP + COL_P + COL_T)


def write_report(path, header, items, x, stamp):
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# 本次测试 x={x} (0x{x:x})  at {stamp}\n")
            f.write(header + "\n")
            f.write(fmt_header() + "\n")
            f.write(fmt_sep() + "\n")
            for ip, p, t in items:
                f.write(fmt_row(ip, p, t) + "\n")
        return True
    except Exception as e:
        WRITE_FAILS.append(os.path.basename(path))
        print(f"[WARN] 写 {path} 失败: {e}")
        return False


def get_x():
    if len(sys.argv) < 2:
        return DEFAULT_X
    try:
        # 支持 25 / 0x19
        x = int(sys.argv[1], 0)
    except ValueError:
        print(f"参数 {sys.argv[1]} 不是整数，使用默认 x={DEFAULT_X}")
        return DEFAULT_X
    if not (1 <= x <= 65535):
        print(f"x 必须在 1~65535（16 位段），当前 {x}，使用默认 x={DEFAULT_X}")
        return DEFAULT_X
    return x


def load_ips(path):
    raw = []
    skipped = []
    with open(path, encoding="utf-8-sig") as f:
        for l in f:
            s = l.strip()
            if not s or s.startswith("#"):
                continue
            if s.upper().startswith("IP") or s.startswith("---"):
                continue
            if not _is_valid_ipv6_placeholder(s):
                skipped.append(s)
                continue
            raw.append(s)

    seen = set()
    deduped = []
    dup = 0
    for ip in raw:
        if ip in seen:
            dup += 1
            continue
        seen.add(ip)
        deduped.append(ip)

    return deduped, skipped, dup, len(raw)


def main():
    x_value = get_x()

    if not os.path.isfile(INPUT_FILE):
        print(f"找不到输入文件: {INPUT_FILE}")
        sys.exit(1)

    ips, skipped, dup, raw_count = load_ips(INPUT_FILE)
    total = len(ips)

    if dup:
        print(f"输入文件 {INPUT_FILE} | 原始 {raw_count} 行 → 去重后 {total} 行"
              f"（去掉 {dup} 个重复）")
    else:
        print(f"输入文件 {INPUT_FILE} | 共 {total} 行占位符")

    if skipped:
        print(f"  [SKIP] {len(skipped)} 行非法格式（已忽略）:")
        for s in skipped[:10]:
            print(f"    {s!r}")
        if len(skipped) > 10:
            print(f"    ... 还有 {len(skipped) - 10} 行")

    platform_name = "Windows" if IS_WIN else ("macOS" if IS_MAC else "Linux")
    print(f"平台 {platform_name}（IPv6）| 本次 x = {x_value} (0x{x_value:x})")
    print(f"并发 {MAX_WORKERS} | ping {PING_TIMEOUT_MS}ms(重试{PING_RETRY}) "
          f"| tcp {TCP_TIMEOUT}s:{TCP_PORT}(重试{TCP_RETRY})")

    start = time.time()
    stamp = time.strftime('%Y-%m-%d %H:%M:%S')

    results = []
    done = 0
    err_count = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(test_one, ip, x_value) for ip in ips]
        for fut in as_completed(futures):
            try:
                placeholder, p, t = fut.result()
            except Exception as e:
                err_count += 1
                done += 1
                print(f"  [ERROR] future 异常: {e}")
                continue
            done += 1
            if p is not None or t is not None:
                results.append((placeholder, p, t))
            if done % 200 == 0 or done == total:
                print(f"  进度 {done}/{total} | 能通 {len(results)} "
                      f"| 用时 {time.time()-start:.1f}s")

    results.sort(key=lambda r: ip_sort_key(r[0]))

    try:
        with open(OUT_ALL, "w", encoding="utf-8") as f:
            f.write(f"# 本次测试 x={x_value} (0x{x_value:x}) at {stamp} | "
                    f"全部能通（按 IPv6 数值升序）\n")
            f.write(fmt_header() + "\n")
            f.write(fmt_sep() + "\n")
            for ip, p, t in results:
                f.write(fmt_row(ip, p, t) + "\n")
    except Exception as e:
        WRITE_FAILS.append(os.path.basename(OUT_ALL))
        print(f"[WARN] 写 {OUT_ALL} 失败: {e}")

    ping_list = [(ip, p, t) for ip, p, t in results if p is not None]
    ping_list.sort(key=lambda r: (r[1], r[2] if r[2] is not None else 999999))
    write_report(OUT_SORT_PING, "# 按 ping 延迟升序（仅含 ping 通的 IP）",
                 ping_list, x_value, stamp)

    tcp_list = [(ip, p, t) for ip, p, t in results if t is not None]
    tcp_list.sort(key=lambda r: (r[2], r[1] if r[1] is not None else 999999))
    write_report(OUT_SORT_TCPING, "# 按 tcping 延迟升序（仅含 tcping 通的 IP）",
                 tcp_list, x_value, stamp)

    range_0_100 = [
        (ip, p, t) for ip, p, t in results
        if p is not None and t is not None and 0 <= p <= 100 and 0 <= t <= 100
    ]
    range_100_200 = [
        (ip, p, t) for ip, p, t in results
        if p is not None and t is not None and 100 < p <= 200 and 100 < t <= 200
    ]
    range_0_100.sort(key=lambda r: (r[2], r[1]))
    range_100_200.sort(key=lambda r: (r[2], r[1]))

    write_report(OUT_RANGE_0_100,
                 "# ping 与 tcping 均在 0~100ms（含 100）| 按 tcping 升序",
                 range_0_100, x_value, stamp)
    write_report(OUT_RANGE_100_200,
                 "# ping 与 tcping 均在 100~200ms（不含 100，含 200）| 按 tcping 升序",
                 range_100_200, x_value, stamp)

    if len(range_0_100) >= MIN_RANGE_0_100:
        check_items = range_0_100
        check_header = (f"# 仅写入 range_0_100（{len(range_0_100)} 个，"
                        f">={MIN_RANGE_0_100}）")
    else:
        check_items = sorted(range_0_100 + range_100_200, key=lambda r: (r[2], r[1]))
        check_header = (
            f"# range_0_100 仅 {len(range_0_100)} 个（<{MIN_RANGE_0_100}），"
            f"合并 range_0_100 + range_100_200（共 {len(check_items)} 个）"
        )
    write_report(OUT_CHECK, check_header, check_items, x_value, stamp)

    try:
        with open(OUT_HISTORY, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t"
                    f"x={x_value}\t能通={len(results)}\t"
                    f"ping通={len(ping_list)}\ttcp通={len(tcp_list)}\t"
                    f"0-100={len(range_0_100)}\t100-200={len(range_100_200)}\t"
                    f"err={err_count}\n")
    except Exception as e:
        print(f"[WARN] 写 {OUT_HISTORY} 失败（不影响结果文件）: {e}")

    print(f"\n总用时 {time.time()-start:.1f}s")
    print(f"能通 {len(results)} | ping 通 {len(ping_list)} | tcping 通 {len(tcp_list)}")
    if err_count:
        print(f"[WARN] future 异常 {err_count} 次（不影响其他结果）")
    if WRITE_FAILS:
        print(f"[WARN] 以下结果文件写入失败（可能被占用）: {', '.join(WRITE_FAILS)}")
        print("       数据本身没问题，关闭对应文件后重跑，或手动重命名再跑即可。")
    print(f"0-100ms（双通）  : {len(range_0_100)}  -> {OUT_RANGE_0_100}")
    print(f"100-200ms（双通）: {len(range_100_200)} -> {OUT_RANGE_100_200}")
    print(f"check-v6.txt     : {len(check_items)} 条 -> {OUT_CHECK}")
    print(f"  规则: {check_header}")

    print("\n=== 0-100ms 前 10 ===")
    print(fmt_header()); print(fmt_sep())
    for ip, p, t in range_0_100[:10]:
        print(fmt_row(ip, p, t))

    print("\n=== 100-200ms 前 10 ===")
    print(fmt_header()); print(fmt_sep())
    for ip, p, t in range_100_200[:10]:
        print(fmt_row(ip, p, t))


if __name__ == "__main__":
    main()