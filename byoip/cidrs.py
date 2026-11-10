import os
from ipaddress import ip_network

SRC = "all-v4.txt"

# 1) 读取 all-v4.txt
cidrs = []
with open(SRC, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):   # 跳过空行和注释
            continue
        cidrs.append(line)

# 2) 收集所有 /24 前缀，最后一段替换为 x
ips = []
seen = set()
for cidr in cidrs:
    try:
        net = ip_network(cidr, strict=False)   # strict=False：允许 103.21.244.5/22 这种写法
    except ValueError as e:
        print("跳过无效 CIDR:", cidr, "->", e)
        continue

    if net.version != 4:
        print("跳过非 IPv4:", cidr)
        continue

    if net.prefixlen < 24:
        subs = net.subnets(new_prefix=24)
    else:
        # /24 或比 /24 更小（/25、/32…），直接取其所在 /24
        subs = [net]

    for sub in subs:
        prefix = str(sub.network_address).rsplit(".", 1)[0]
        item = f"{prefix}.x"
        if item not in seen:                   # 去重（CIDR 重叠时有用）
            seen.add(item)
            ips.append(item)

# 3) 目标路径
out1 = "cf-v4-24.txt"
out2_dir = "check-v4"
out2 = os.path.join(out2_dir, "cf-v4-24.txt")

os.makedirs(out2_dir, exist_ok=True)

content = "\n".join(ips) + "\n"

with open(out1, "w", encoding="utf-8") as f:
    f.write(content)

with open(out2, "w", encoding="utf-8") as f:
    f.write(content)

print("读取 CIDR 条数:", len(cidrs))
print("生成数量:", len(ips))
print("输出文件1:", os.path.abspath(out1))
print("输出文件2:", os.path.abspath(out2))