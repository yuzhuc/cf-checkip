import os, sys, re, time, socket, subprocess, threading, ipaddress
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

config = {
    'ip_list':         os.path.join(BASE_DIR, 'check-v4.txt'),
    'exclude_file':    os.path.join(BASE_DIR, 'exclude.txt'),
    'out_file':        os.path.join(BASE_DIR, 'out.txt'),
    'log_file':        os.path.join(BASE_DIR, 'outip.log'),
    'host':            None,          # 从 URL 自动解析
    'url':             'https://time.is',
    'retry':           1,             # TCP 探活失败重试次数（=2 次尝试）
    'http_retry':      1,             # curl 返回 000 时额外重试次数
    'tcp_port':        None,          # None = 从 URL 派生；显式设置则独立使用
    'tcp_timeout':     2.0,
    'connect_timeout': 5,
    'max_time':        15,
    'concurrency':     30,
    'ua':              ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                        'AppleWebKit/537.36 (KHTML, like Gecko) '
                        'Chrome/124.0.0.0 Safari/537.36'),
    'default_x':       25,
}

DEV_NULL = os.devnull
IS_WIN = (os.name == 'nt')
CREATE_NO_WINDOW = 0x08000000 if IS_WIN else 0
SEP = '\x1f'

# ---------- URL 解析：host / --resolve 端口 / tcp_port ----------
try:
    _url_parsed = urlparse(config['url'])
    if not _url_parsed.hostname:
        raise ValueError("URL 缺少 hostname（例如 https://time.is）")
    _resolve_port = _url_parsed.port or (443 if _url_parsed.scheme == 'https' else 80)
except ValueError as e:
    print(f"[ERR] URL 解析失败 ({config['url']}): {e}", file=sys.stderr)
    sys.exit(1)

config['host'] = _url_parsed.hostname
_tcp_port_explicit = config['tcp_port'] is not None
if config['tcp_port'] is None:
    config['tcp_port'] = _resolve_port

X_RE = re.compile(r'本次测试\s*x\s*=\s*(\d+)', re.IGNORECASE)
IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$|^\d{1,3}(?:\.\d{1,3}){2}\.x$', re.IGNORECASE)
NUM_RE = re.compile(r'^\d+$')

COL_IP, COL_P, COL_T, COL_L = 18, 8, 8, 10

print_lock = threading.Lock()


def _valid_ipv4_format(s):
    """校验 4 段 0–255；.x 占位符末段按 0 校验"""
    if s.lower().endswith('.x'):
        s = s[:-1] + '0'
    parts = s.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _clean_latency_val(v):
    """ping/tcp 列校验：只接受纯数字或 '-'，其余替换为 '-'"""
    if v is None:
        return '-'
    s = str(v).strip()
    if s == '-' or NUM_RE.match(s):
        return s
    return '-'


def fmt_cell(v, width):
    s = '-' if v is None else str(v)
    return f"{s:>{width}}"


def fmt_row(ip, p, t, lat):
    return f"{ip:<{COL_IP}}{fmt_cell(p, COL_P)}{fmt_cell(t, COL_T)}{fmt_cell(lat, COL_L)}"


def fmt_header():
    return f"{'IP':<{COL_IP}}{'ping':>{COL_P}}{'tcp':>{COL_T}}{'latency':>{COL_L}}"


def fmt_sep():
    return "-" * (COL_IP + COL_P + COL_T + COL_L)


# ---------- 解析 check-v4.txt ----------
def parse_input(path, override_x=None):
    """返回 (x_value, header_lines, items, skipped, x_source, file_x)
    file_x: 文件头注释里的 x（不受 override 影响），用于对比提示
    """
    if not os.path.isfile(path):
        return None, [], [], [], 'missing', None

    x_value = None
    x_source = None
    file_x = None
    header_lines = []
    items = []
    skipped = []

    with open(path, encoding='utf-8-sig', errors='ignore') as f:
        for raw in f:
            s = raw.rstrip('\r\n')
            strip = s.strip()
            if not strip:
                continue
            if strip.startswith('#'):
                # 过滤旧版 check-http.py 写进来的两行，避免 out.txt 出现双份
                if (strip.startswith('# --- 以下为 HTTP 200')
                        or strip.startswith('# HTTP 200 通过 at')):
                    continue
                header_lines.append(strip)
                m = X_RE.search(strip)
                if m:
                    v = int(m.group(1))
                    if x_value is None:
                        x_value = v
                        x_source = '文件头注释'
                    if file_x is None:
                        file_x = v
                continue

            tok = strip.split()
            if not tok:
                continue
            first = tok[0]
            if first.upper() == 'IP' or first.startswith('---'):
                continue
            if ':' in first:
                continue
            if not IP_RE.match(first) or not _valid_ipv4_format(first):
                skipped.append(strip)
                continue
            p_val = _clean_latency_val(tok[1] if len(tok) > 1 else '-')
            t_val = _clean_latency_val(tok[2] if len(tok) > 2 else '-')
            items.append((first, p_val, t_val))

    # 文件头注释里的 x 也要校验范围；越界时丢弃
    if file_x is not None and not (1 <= file_x <= 254):
        print(f"[WARN] 文件头注释 x={file_x} 超出 1~254，忽略该值")
        if x_source == '文件头注释':
            x_value = None
            x_source = None
        file_x = None

    if override_x is not None:
        x_value = override_x
        x_source = '命令行参数'
    if x_value is None:
        x_value = config['default_x']
        x_source = '默认值(未找到注释!)'

    return x_value, header_lines, items, skipped, x_source, file_x


def resolve(ph, x):
    ph = ph.strip()
    if ph.lower().endswith('.x'):
        return f"{ph.rsplit('.', 1)[0]}.{x}"
    return ph


# ---------- 排除名单（支持 CIDR） ----------
def read_exclude(path):
    """返回 ip_network 列表；文件不存在时创建带说明的空文件"""
    if not os.path.isfile(path):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("# 排除名单：一行一个 CIDR 或 IP\n")
                f.write("#   104.16.0.0/24     整个 /24 段（256 个）\n")
                f.write("#   104.16.0.0/16     整个 /16 段（65536 个）\n")
                f.write("#   104.16.2.5        单个 IP\n")
                f.write("#   104.16.2.x        占位符，等价 104.16.2.0/24\n")
                f.write("# 以 # 开头的行为注释\n")
            print(f"[INFO] exclude.txt 不存在，已自动创建: {path}")
        except Exception as e:
            print(f"[WARN] 无法创建 {path}: {e}，本次不排除任何 IP")
        return []

    nets = []
    with open(path, encoding='utf-8-sig', errors='ignore') as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            tok = s.split()[0]
            if tok.lower().endswith('.x'):
                tok = tok[:-1] + '0/24'
            try:
                nets.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                print(f"[WARN] exclude 非法条目: {tok}")
    return nets


def is_excluded(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


def tcp_ping(ip, timeout_s):
    t0 = time.perf_counter()
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        s.connect((ip, config['tcp_port']))
        return True, round((time.perf_counter() - t0) * 1000)
    except Exception:
        return False, None
    finally:
        if s:
            try: s.close()
            except Exception: pass


def probe_with_retry(ip):
    for _ in range(1 + config['retry']):
        ok, lat = tcp_ping(ip, config['tcp_timeout'])
        if ok:
            return True, lat
    return False, None


# ---------- HTTP（含 000 重试） ----------
def _http_once(ip):
    resolve_arg = f"{config['host']}:{_resolve_port}:{ip}"
    args = [
        '--noproxy', '*',
        '-k', '-s',
        '-L', '--max-redirs', '0',
        '--compressed',
        '-A', config['ua'],
        '-o', DEV_NULL,
        '-w', f'%{{http_code}}{SEP}%{{remote_ip}}{SEP}%{{url_effective}}',
        '--connect-timeout', str(config['connect_timeout']),
        '--max-time', str(config['max_time']),
        '--resolve', resolve_arg,
        config['url'],
    ]
    try:
        r = subprocess.run(
            ['curl'] + args,
            capture_output=True, text=True, encoding='utf-8', errors='ignore',
            timeout=config['max_time'] + 10,
            creationflags=CREATE_NO_WINDOW,
        )
        out = (r.stdout or '').strip() or f'000{SEP}{SEP}'
    except Exception:
        out = f'000{SEP}{SEP}'
    p = out.split(SEP)
    remote = p[1] if len(p) > 1 else ''
    final_url = p[2] if len(p) > 2 else ''
    # 老 curl 不识别 %{remote_ip} / %{url_effective} 时原样输出 "%{...}"，当作空处理
    if remote.startswith('%{'):
        remote = ''
    if final_url.startswith('%{'):
        final_url = ''
    return {
        'code':      p[0] if p else '000',
        'remote':    remote,
        'final_url': final_url,
    }


def http_probe(ip, retry_on_fail=None):
    if retry_on_fail is None:
        retry_on_fail = config['http_retry']
    h = {'code': '000', 'remote': '', 'final_url': ''}
    for attempt in range(1 + retry_on_fail):
        h = _http_once(ip)
        if h['code'] not in ('000', ''):
            return h
        if attempt < retry_on_fail:
            time.sleep(0.3)
    return h


# ---------- 单个 IP ----------
def test_one(placeholder, real, p_val, t_val, idx, total):
    ok, lat = probe_with_retry(real)
    if not ok:
        return {
            'idx': idx, 'placeholder': placeholder, 'real': real,
            'ping': p_val, 'tcp': t_val, 'latency': None, 'res': 'pfail',
            'mismatch': False,
            'line': f"{placeholder}  real={real}  tcp=FAIL  latency=-  http=skip",
        }

    lat_str = '-' if lat is None else f"{lat}ms"
    h = http_probe(real)
    line = (f"{placeholder}  real={real}  tcp=OK  latency={lat_str}  "
            f"http={h['code']}  remote={h['remote']}  finalURL={h['final_url']}")

    if h['code'] == '200':
        # remote_ip 为空：curl 版本太老（%{remote_ip} 不被识别）或未返回，放行但提示
        if not h['remote']:
            line += "  [REMOTE_EMPTY] curl 未返回 remote_ip，无法校验 --resolve"
            return {
                'idx': idx, 'placeholder': placeholder, 'real': real,
                'ping': p_val, 'tcp': t_val, 'latency': lat, 'res': 'ok',
                'mismatch': False, 'line': line,
            }
        # remote_ip 非空且不等于指定 IP：--resolve 失效，判 bad
        if h['remote'] != real:
            line += f"  [MISMATCH] expected={real} got={h['remote']}"
            return {
                'idx': idx, 'placeholder': placeholder, 'real': real,
                'ping': p_val, 'tcp': t_val, 'latency': lat, 'res': 'bad',
                'mismatch': True, 'line': line,
            }
        return {
            'idx': idx, 'placeholder': placeholder, 'real': real,
            'ping': p_val, 'tcp': t_val, 'latency': lat, 'res': 'ok',
            'mismatch': False, 'line': line,
        }
    return {
        'idx': idx, 'placeholder': placeholder, 'real': real,
        'ping': p_val, 'tcp': t_val, 'latency': lat, 'res': 'bad',
        'mismatch': False, 'line': line,
    }


def _clean_line(s):
    """清理换行，防止破坏 log 逐行格式"""
    return s.replace('\r', ' ').replace('\n', ' ')


def main():
    override_x = None
    if len(sys.argv) > 1:
        try:
            override_x = int(sys.argv[1])
            if not (1 <= override_x <= 254):
                print(f"[WARN] 参数 x={override_x} 超出 1~254，忽略，使用文件头 x")
                override_x = None
        except ValueError:
            print(f"参数 {sys.argv[1]} 不是整数，忽略，使用文件头 x")

    if not os.path.isfile(config['ip_list']):
        print(f"[ERR] not found: {config['ip_list']}", file=sys.stderr)
        sys.exit(1)

    try:
        cr = subprocess.run(
            ['curl', '--version'],
            capture_output=True, text=True, timeout=5,
            creationflags=CREATE_NO_WINDOW,
        )
        if cr.returncode != 0:
            print(f"[ERR] curl 异常退出 (code={cr.returncode}): "
                  f"{(cr.stderr or '').strip()}", file=sys.stderr)
            sys.exit(1)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"[ERR] curl 不可用: {e}", file=sys.stderr)
        sys.exit(1)

    x_value, header_lines, items, skipped, x_source, file_x = parse_input(
        config['ip_list'], override_x)

    print(f"input   : {config['ip_list']}")
    print(f"url     : {config['url']}")
    print(f"host    : {config['host']}  (从 URL 解析)")
    if _tcp_port_explicit:
        if config['tcp_port'] != _resolve_port:
            print(f"tcp     : {config['tcp_port']}  (显式设置) | --resolve 端口 {_resolve_port}")
        else:
            print(f"tcp     : {config['tcp_port']}  (显式设置，与 URL 一致)")
    else:
        print(f"tcp     : {config['tcp_port']}  (从 URL 派生)")
    print(f"x       : {x_value}  ({x_source})")
    if x_source.startswith('默认值'):
        print(f"[WARN] 未在输入文件中找到 '# 本次测试 x=N'，"
              f"回退 default_x={x_value}，请确认是否正确")
    if (override_x is not None and file_x is not None
            and override_x != file_x):
        print(f"[WARN] 命令行 x={override_x} 与文件注释 x={file_x} 不一致，"
              f"out.txt 中 ping/tcp 列仍取自 x={file_x} 的原始数据")

    # 去重
    raw_count = len(items)
    seen = set()
    items_deduped = []
    for ph, p_val, t_val in items:
        key = ph.strip().lower()
        if key in seen:
            continue
        seen.add(key)
        items_deduped.append((ph, p_val, t_val))
    dup = raw_count - len(items_deduped)
    items = items_deduped
    print(f"count   : {raw_count}" + (f"  (去掉 {dup} 个重复 -> {len(items)})" if dup else ""))

    if skipped:
        print(f"  [SKIP] {len(skipped)} 行非法格式（已忽略）:")
        for s in skipped[:10]:
            print(f"    {s!r}")
        if len(skipped) > 10:
            print(f"    ... 还有 {len(skipped) - 10} 行")

    if header_lines:
        print(f"header  : {len(header_lines)} 行注释将写入 out.txt")

    exclude_nets = read_exclude(config['exclude_file'])
    print(f"exclude : {len(exclude_nets)} 条规则  <- {config['exclude_file']}")

    kept = []
    excluded_count = 0
    for ph, p_val, t_val in items:
        real = resolve(ph, x_value)
        if is_excluded(real, exclude_nets):
            excluded_count += 1
            continue
        kept.append((ph, real, p_val, t_val))

    total = len(kept)
    print(f"after   : {total}  (excluded {excluded_count})")

    run_stamp = time.strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(config['log_file'], 'w', encoding='utf-8') as logf:
            logf.write(f"# ===== run at {run_stamp} | x={x_value} ({x_source}) | "
                       f"input={raw_count} | kept={total} =====\n")
            logf.write("# 字段: <占位符>  real=<真实IP>  tcp=OK/FAIL  "
                       "latency=<本次TCP握手ms>  http=<状态码/000/skip>  "
                       "remote=<curl实际连接IP，空表示老curl不返回>  finalURL=<最终URL>\n")
            logf.write("# http=000: curl 连接失败/超时/TLS 失败（已重试 http_retry 次仍失败）；"
                       "http=skip: TCP 未通，未做 HTTP\n")
    except Exception as e:
        print(f"[WARN] 初始化 {config['log_file']} 失败: {e}")

    # out.txt 注释头第二行：根据 file_x 与 x_value 的关系动态生成措辞
    if file_x is None:
        ping_tcp_note = "ping/tcp 取自 check-v4.txt 原始数据（文件头未找到 x 注释）"
    elif file_x == x_value:
        ping_tcp_note = (f"ping/tcp 取自 check-v4.txt 中 x={file_x} 的原始数据"
                         f"（与本次 x 一致）")
    else:
        ping_tcp_note = (f"ping/tcp 取自 check-v4.txt 中 x={file_x} 的原始数据"
                         f"（与本次 x={x_value} 不同）")

    out_header = (
        f"# HTTP 200 通过 at {run_stamp}（x={x_value}，{x_source}；"
        f"仅保留 curl 返回 200 的 IP；不跟随重定向；"
        f"{ping_tcp_note}；"
        f"latency 为本次 TCP 握手最后一次成功值，单位 ms）\n"
    )

    if total == 0:
        print("nothing to test.")
        try:
            with open(config['log_file'], 'a', encoding='utf-8') as logf:
                logf.write("# nothing to test (after exclude / dedupe)\n")
        except Exception as e:
            print(f"[WARN] 写 {config['log_file']} 失败: {e}")
        try:
            with open(config['out_file'], 'w', encoding='utf-8') as outf:
                for h in header_lines:
                    outf.write(h + '\n')
                outf.write("# --- 以下为 HTTP 200 通过结果 ---\n")
                outf.write(out_header)
                outf.write(fmt_header() + '\n')
                outf.write(fmt_sep() + '\n')
        except Exception as e:
            print(f"[WARN] 写 {config['out_file']} 失败: {e}")
        return

    print(f"start   : concurrency={config['concurrency']}, "
          f"probe=tcp/{config['tcp_port']}, tcp_retry={config['retry']}, "
          f"http_retry={config['http_retry']}\n")

    start = time.time()
    results = [None] * total
    cursor = [0]
    done = [0]
    lock = threading.Lock()

    def worker():
        while True:
            with lock:
                i = cursor[0]
                cursor[0] += 1
            if i >= total:
                break
            ph, real, p_val, t_val = kept[i]
            try:
                r = test_one(ph, real, p_val, t_val, i, total)
            except Exception as e:
                r = {
                    'idx': i, 'placeholder': ph, 'real': real,
                    'ping': p_val, 'tcp': t_val, 'latency': None, 'res': 'pfail',
                    'mismatch': False,
                    'line': f"{ph}  real={real}  ERROR={e}",
                }
            results[i] = r
            with lock:
                done[0] += 1
                if done[0] % 200 == 0 or done[0] == total:
                    with print_lock:
                        print(f"  --- 进度 {done[0]}/{total} | "
                              f"用时 {time.time()-start:.1f}s ---")

    workers = max(1, min(config['concurrency'], total))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in [ex.submit(worker) for _ in range(workers)]:
            fut.result()

    # 按输入顺序落盘
    tcp_fail = http200 = http_bad = mismatch = 0
    ok_rows = []
    write_logs_ok = True

    def tally():
        nonlocal tcp_fail, http200, http_bad, mismatch, ok_rows
        tcp_fail = http200 = http_bad = mismatch = 0
        ok_rows = []
        for r in results:
            if r is None:
                continue
            if r['res'] == 'pfail':
                tcp_fail += 1
            elif r['res'] == 'ok':
                http200 += 1
                ok_rows.append((r['placeholder'], r['ping'], r['tcp'],
                                r['latency'] if r['latency'] is not None else '-'))
            else:
                http_bad += 1
                if r.get('mismatch'):
                    mismatch += 1

    try:
        with open(config['log_file'], 'a', encoding='utf-8') as logf:
            for r in results:
                if r is None:
                    continue
                logf.write(_clean_line(r['line']) + '\n')
                if r['res'] == 'pfail':
                    tcp_fail += 1
                elif r['res'] == 'ok':
                    http200 += 1
                    ok_rows.append((r['placeholder'], r['ping'], r['tcp'],
                                    r['latency'] if r['latency'] is not None else '-'))
                else:
                    http_bad += 1
                    if r.get('mismatch'):
                        mismatch += 1
    except Exception as e:
        write_logs_ok = False
        print(f"[WARN] 写 {config['log_file']} 失败: {e}")
        tally()

    try:
        with open(config['out_file'], 'w', encoding='utf-8') as outf:
            for h in header_lines:
                outf.write(h + '\n')
            outf.write("# --- 以下为 HTTP 200 通过结果 ---\n")
            outf.write(out_header)
            outf.write(fmt_header() + '\n')
            outf.write(fmt_sep() + '\n')
            for ph, p_val, t_val, lat in ok_rows:
                outf.write(fmt_row(ph, p_val, t_val, lat) + '\n')
    except Exception as e:
        print(f"[WARN] 写 {config['out_file']} 失败: {e}")

    elapsed = time.time() - start
    print()
    print('=' * 50)
    print(f"DONE: total={total}  excluded={excluded_count}")
    print(f"      tcp_fail={tcp_fail}  http200={http200}  other={http_bad}"
          + (f"  (mismatch={mismatch})" if mismatch else ""))
    print(f"      用时 {elapsed:.1f}s")
    print(f"out   : {config['out_file']}   ({len(ok_rows)} 条, 按输入顺序)")
    if write_logs_ok:
        print(f"log   : {config['log_file']}  (run at {run_stamp})")
    else:
        print(f"log   : {config['log_file']}  (写入失败，请检查是否被占用)")
    print('=' * 50)


if __name__ == '__main__':
    main()