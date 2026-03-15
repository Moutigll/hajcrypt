#!/usr/bin/env bash
set -euo pipefail

FT_SSL=./ft_ssl
OPENSSL=openssl
RHASH=rhash
OUTPUT=benchmark.html
TMPDIR=$(mktemp -d /tmp/ft_ssl_bench_XXXXXX)

# Single large file size: 2GB (enough to reach max speed)
SIZE=2147483648
FILE="$TMPDIR/test.bin"

# Fixed key for AES-128-ECB
AES_KEY="00112233445566778899aabbccddeeff"

# Quick checks
if [ ! -x "$FT_SSL" ]; then
  echo "Error: $FT_SSL not found or not executable" >&2
  exit 1
fi
if ! command -v $OPENSSL >/dev/null 2>&1; then
  echo "Warning: openssl not found in PATH (MD5/SHA256/Blake2b/AES will be skipped)" >&2
  OPENSSL=""
fi
if ! command -v $RHASH >/dev/null 2>&1; then
  echo "Warning: rhash not found in PATH (Whirlpool will be skipped)" >&2
  RHASH=""
fi

echo "Benchmark in $TMPDIR"
echo "Creating sparse file $FILE (${SIZE} bytes)..."
truncate -s "$SIZE" "$FILE"

# Measure single run: returns elapsed nanoseconds
_run_once_ns() {
  local start end
  start=$(date +%s%N)
  "$@" > /dev/null 2>&1
  end=$(date +%s%N)
  echo $((end - start))
}

# Measure average MB/s for given algo/bin/file
# Runs: 1 warmup + 3 measured runs
measure_avg_mbps() {
  local algo="$1" file="$2" bin="$3"
  local rounds=4  # 1 warmup + 3 measured
  local sum_ns=0
  local measured=0
  local i
  
  for i in $(seq 1 $rounds); do
    if [ "$bin" = "$OPENSSL" ] && [ -n "$OPENSSL" ]; then
      case "$algo" in
        md5)      ns=$(_run_once_ns $bin dgst -md5 "$file") ;;
        sha256)   ns=$(_run_once_ns $bin dgst -sha256 "$file") ;;
        blake2b)  ns=$(_run_once_ns $bin dgst -blake2b512 "$file") ;;
        aes128)   ns=$(_run_once_ns $bin enc -aes-128-ecb -K "$AES_KEY" -nosalt -in "$file" -out /dev/null) ;;
        *)        ns=0 ;;
      esac
    elif [ "$bin" = "$RHASH" ] && [ -n "$RHASH" ]; then
      ns=$(_run_once_ns $bin --whirlpool "$file")
    elif [ "$bin" = "$FT_SSL" ]; then
      case "$algo" in
        md5|sha256|whirlpool|blake2b)
          ns=$(_run_once_ns "$bin" "$algo" "$file") ;;
        aes128)
          ns=$(_run_once_ns "$bin" aes-128-ecb -k "$AES_KEY" -i "$file" -o /dev/null) ;;
        *)
          ns=0 ;;
      esac
    else
      ns=0  # tool not available
    fi

    # Ignore first run (warmup)
    if [ "$i" -gt 1 ]; then
      sum_ns=$((sum_ns + ns))
      measured=$((measured + 1))
    fi
  done

  if [ "$measured" -eq 0 ]; then
    echo "0.00"
    return
  fi

  # Compute average MB/s (1 MB = 1048576 bytes)
  awk -v size="$SIZE" -v sum_ns="$sum_ns" -v m="$measured" '
    BEGIN {
      time_s = (sum_ns / m) / 1e9;
      if (time_s > 0)
        printf "%.2f", size / time_s / 1048576;
      else
        printf "0.00";
    }'
}

# Declare associative arrays
declare -A ft_vals
declare -A other_vals
ALGOS=("md5" "sha256" "blake2b" "whirlpool" "aes128")
ALGO_NAMES=("MD5" "SHA256" "Blake2b" "Whirlpool" "AES-128-ECB")

# Run benchmarks for each algorithm
for idx in "${!ALGOS[@]}"; do
  algo="${ALGOS[$idx]}"
  name="${ALGO_NAMES[$idx]}"
  echo -e "\n--- $name ---"
  
  # ft_ssl
  echo "  ft_ssl..."
  v=$(measure_avg_mbps "$algo" "$FILE" "$FT_SSL")
  ft_vals["$algo"]="$v"
  echo "    -> $v MB/s"
  
  # Other tool (openssl or rhash)
  other_tool=""
  if [ "$algo" = "whirlpool" ]; then
    other_tool="$RHASH"
  else
    other_tool="$OPENSSL"
  fi
  
  if [ -n "$other_tool" ]; then
    echo "  ${other_tool}..."
    v=$(measure_avg_mbps "$algo" "$FILE" "$other_tool")
    other_vals["$algo"]="$v"
    echo "    -> $v MB/s"
  else
    other_vals["$algo"]="0.00"
    echo "    -> (tool not available)"
  fi
done

# Cleanup
rm -rf "$TMPDIR"

# Generate HTML with grouped bar chart
cat > "$OUTPUT" <<EOF
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>ft_ssl Benchmark - Speed Comparison (MB/s)</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{font-family:Arial;background:#111;color:#fff;padding:20px}
canvas{background:#fff;border-radius:8px;display:block;margin:20px auto}
.legend{position:fixed;top:12px;right:12px;background:#222;padding:8px;border-radius:6px}
.box{width:12px;height:12px;display:inline-block;margin-right:8px}
.small{font-size:12px;color:#ccc}
table{width:80%;margin:20px auto;border-collapse:collapse;background:#222}
th,td{padding:10px;text-align:center;border:1px solid #444}
th{background:#333}
</style>
</head>
<body>
<h1 style="text-align:center">ft_ssl vs OpenSSL/rhash — Speed Comparison (MB/s)</h1>
<div class="legend">
  <div><span class="box" style="background:#4CAF50"></span><span class="small">ft_ssl</span></div>
  <div><span class="box" style="background:#F44336"></span><span class="small">OpenSSL/rhash</span></div>
</div>

<canvas id="benchmark" width="900" height="500"></canvas>

<table>
  <tr><th>Algorithm</th><th>ft_ssl (MB/s)</th><th>OpenSSL/rhash (MB/s)</th><th>Ratio</th></tr>
EOF

# Add table rows with ratio (using awk for floating point)
for i in "${!ALGOS[@]}"; do
  algo="${ALGOS[$i]}"
  name="${ALGO_NAMES[$i]}"
  ft="${ft_vals[$algo]:-0.00}"
  other="${other_vals[$algo]:-0.00}"
  
  # Calculate ratio (ft_ssl / other) safely with awk
  ratio=$(awk -v ft="$ft" -v other="$other" 'BEGIN {
    if (other > 0) printf "%.2fx", ft/other; else print "N/A"
  }')
  
  cat >> "$OUTPUT" <<EOF
  <tr><td>$name</td><td>$ft</td><td>$other</td><td>$ratio</td></tr>
EOF
done

cat >> "$OUTPUT" <<EOF
</table>

<script>
const ctx = document.getElementById('benchmark').getContext('2d');
new Chart(ctx, {
  type: 'bar',
  data: {
    labels: [$(printf '"%s",' "${ALGO_NAMES[@]}" | sed 's/,$//')],
    datasets: [
      {
        label: 'ft_ssl',
        data: [${ft_vals[md5]:-0.00}, ${ft_vals[sha256]:-0.00}, ${ft_vals[blake2b]:-0.00}, ${ft_vals[whirlpool]:-0.00}, ${ft_vals[aes128]:-0.00}],
        backgroundColor: '#4CAF50',
      },
      {
        label: 'OpenSSL / rhash',
        data: [${other_vals[md5]:-0.00}, ${other_vals[sha256]:-0.00}, ${other_vals[blake2b]:-0.00}, ${other_vals[whirlpool]:-0.00}, ${other_vals[aes128]:-0.00}],
        backgroundColor: '#F44336',
      }
    ]
  },
  options: {
    responsive: true,
    plugins: {
      title: {
        display: true,
        text: 'Processing Speed (MB/s) on 2GB file (1 warmup + 3 runs average)'
      },
      legend: { display: false }
    },
    scales: {
      y: {
        beginAtZero: true,
        title: { display: true, text: 'MB/s' }
      }
    }
  }
});
</script>

<p style="text-align:center; color:#ccc">
  File size: 2GB (2147483648 bytes)<br>
  1 warmup run + 3 measured runs per algorithm<br>
  Values 0.00 indicate the tool was not available or measurement failed.
</p>
</body>
</html>
EOF

echo -e "\nDone! Results saved to $OUTPUT"
