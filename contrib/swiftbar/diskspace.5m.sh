#!/bin/bash
# <xbar.title>diskspace</xbar.title>
# <xbar.version>v1.0</xbar.version>
# <xbar.desc>Free space, burn-rate trend, days-to-full, and top growers from `diskspace trend`.</xbar.desc>
# <xbar.dependencies>diskspace,python3</xbar.dependencies>
# <xbar.abouturl>https://github.com/tymrtn/diskspace</xbar.abouturl>
#
# SwiftBar/xbar menu-bar plugin for diskspace. Install: drop (or symlink) this
# file into your SwiftBar plugin folder. Refreshes every 5 minutes (rename to
# change the cadence, e.g. diskspace.1m.sh).
#
# Everything shown comes from `diskspace --json trend` (advisory measurement
# only — this plugin never triggers a deletion) plus one `df` call for the
# live free percentage.

set -euo pipefail

# Find the binary: Homebrew first, then PATH, then a dev build.
DISKSPACE=""
for cand in /opt/homebrew/bin/diskspace /usr/local/bin/diskspace; do
  [ -x "$cand" ] && DISKSPACE="$cand" && break
done
[ -z "$DISKSPACE" ] && DISKSPACE="$(command -v diskspace || true)"
if [ -z "$DISKSPACE" ]; then
  echo "⛁ ?"
  echo "---"
  echo "diskspace binary not found | color=red"
  echo "brew install tymrtn/diskspace/diskspace | font=Menlo size=11"
  exit 0
fi

"$DISKSPACE" --json trend --top 3 2>/dev/null | /usr/bin/python3 -c '
import json, os, subprocess, sys

data = json.load(sys.stdin)
trend = data.get("trend", {})
growers = data.get("growers", [])

# Live free space from df (fast; trend JSON carries only the fit).
st = os.statvfs(os.path.expanduser("~"))
free = st.f_bavail * st.f_frsize
total = st.f_blocks * st.f_frsize
pct = free / total * 100 if total else 100.0

def fmt(b):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1000:
            return f"{b:.1f} {unit}" if unit != "B" else f"{int(b)} B"
        b /= 1000
    return f"{b:.1f} PB"

rate = trend.get("burn_rate_bytes_per_day")
days = trend.get("days_to_full")

# Menu-bar line: free % — red when the forecast or the level is scary.
color = ""
if pct < 5 or (days is not None and days <= 14):
    color = " | color=red"
elif pct < 10 or (days is not None and days <= 30):
    color = " | color=orange"
print(f"⛁ {pct:.1f}%{color}")

print("---")
print(f"Free: {fmt(free)} ({pct:.1f}%)")
if rate is None:
    n = trend.get("samples", 0)
    print(f"Trend: not enough samples yet ({n})")
elif rate > 0:
    print(f"Trend: filling at {fmt(rate)}/day | color=red")
    if days is not None:
        print(f"Full in ~{days} day(s) at this rate | color=red")
else:
    print(f"Trend: reclaiming {fmt(-rate)}/day | color=green")
if growers:
    print("---")
    print("Top growers this week:")
    home = os.path.expanduser("~") + "/"
    for g in growers:
        path = g["path"]
        delta = fmt(g["delta_bytes"])
        if path.rstrip("/") == home.rstrip("/"):
            short = "~"
        elif path.startswith(home):
            short = path[len(home):]
        else:
            short = path
        print(f"+{delta}  {short} | font=Menlo size=11 trim=false")
print("---")
print("Open trend report | bash=" + json.dumps(sys.argv[1] if len(sys.argv) > 1 else "diskspace") + " param1=trend terminal=true")
' "$DISKSPACE"
