#!/usr/bin/env bash
set -euo pipefail

FT_SSL=./ft_ssl
OPENSSL=openssl
RHASH=rhash
OUTPUT=benchmark.html
TMPDIR=$(mktemp -d /tmp/ft_ssl_bench_XXXXXX)

# sizes: 1MB, 10MB, 100MB, 1GB, 2GB, 5GB
SIZES=(1048576 10485760 104857600 1073741824 2147483648 5368709120)

# quick checks
if [ ! -x "$FT_SSL" ]; then
  echo "Error: $FT_SSL not found or not executable" >&2
  exit 1
fi
if ! command -v $OPENSSL >/dev/null 2>&1; then
  echo "Warning: openssl not found in PATH (MD5/SHA256 will be skipped)" >&2
  OPENSSL=""
fi
if ! command -v $RHASH >/dev/null 2>&1; then
  echo "Error: rhash not found in PATH (required for Whirlpool)" >&2
  exit 1
fi

echo "Benchmark in $TMPDIR"

labels=()
md5_ft_vals=()
md5_ssl_vals=()
sha_ft_vals=()
sha_ssl_vals=()
whirlpool_ft_vals=()
whirlpool_rhash_vals=()

# measure single run: returns elapsed nanoseconds
_run_once_ns() {
  # $@ = command... (full command as array)
  local start end
  start=$(date +%s%N)
  # run the command (stdout discarded)
  "$@" > /dev/null 2>&1
  end=$(date +%s%N)
  echo $((end - start))
}

# measure avg seconds for given algo/bin/file with appropriate number of rounds
measure_avg_seconds() {
  local algo="$1" file="$2" bin="$3" size="$4"
  local rounds
  if [ "$size" -lt 1073741824 ]; then
	rounds=6		# 1 warmup + 5 measured
  elif [ "$size" -lt 5368709120 ]; then
	rounds=3		# 1 warmup + 2 measured
  else
	rounds=2		# 1 warmup + 1 measured
  fi

  local sum_ns=0
  local measured=0
  local i
  for i in $(seq 1 $rounds); do
	if [ "$bin" = "$OPENSSL" ]; then
	  if [ "$algo" = "md5" ]; then
		ns=$(_run_once_ns $bin dgst -md5 "$file")
	  elif [ "$algo" = "sha256" ]; then
		ns=$(_run_once_ns $bin dgst -sha256 "$file")
	  else
		ns=0
	  fi
	elif [ "$bin" = "$RHASH" ]; then
	  # rhash --whirlpool filename
	  ns=$(_run_once_ns $bin --whirlpool "$file")
	else
	  # ft_ssl expects: ft_ssl algo filename (md5, sha256, whirlpool)
	  ns=$(_run_once_ns "$bin" "$algo" "$file")
	fi

	# ignore first run
	if [ "$i" -gt 1 ]; then
	  sum_ns=$((sum_ns + ns))
	  measured=$((measured + 1))
	fi
  done

  # avoid division by zero (shouldn't happen)
  if [ "$measured" -eq 0 ]; then
	echo "0.000000"
	return
  fi

  # compute average in seconds with 6 decimals using awk
  awk -v s="$sum_ns" -v m="$measured" 'BEGIN { printf "%.6f", (s / m) / 1e9 }'
}

# main loop
for size in "${SIZES[@]}"; do
  file="$TMPDIR/test_$size.bin"
  echo "Creating sparse file $file (${size} bytes)..."
  truncate -s "$size" "$file"

  labels+=("$size")

  # MD5 ft_ssl
  echo "  MD5 ft_ssl..."
  v=$(measure_avg_seconds md5 "$file" "$FT_SSL" "$size")
  md5_ft_vals+=("$v")
  echo "	-> $v s"

  # MD5 openssl (if available)
  if [ -n "$OPENSSL" ]; then
	echo "  MD5 openssl..."
	v=$(measure_avg_seconds md5 "$file" "$OPENSSL" "$size")
	md5_ssl_vals+=("$v")
	echo "	-> $v s"
  else
	md5_ssl_vals+=("0")
  fi

  # SHA256 ft_ssl
  echo "  SHA256 ft_ssl..."
  v=$(measure_avg_seconds sha256 "$file" "$FT_SSL" "$size")
  sha_ft_vals+=("$v")
  echo "	-> $v s"

  # SHA256 openssl (if available)
  if [ -n "$OPENSSL" ]; then
	echo "  SHA256 openssl..."
	v=$(measure_avg_seconds sha256 "$file" "$OPENSSL" "$size")
	sha_ssl_vals+=("$v")
	echo "	-> $v s"
  else
	sha_ssl_vals+=("0")
  fi

  # Whirlpool ft_ssl
  echo "  Whirlpool ft_ssl..."
  v=$(measure_avg_seconds whirlpool "$file" "$FT_SSL" "$size")
  whirlpool_ft_vals+=("$v")
  echo "	-> $v s"

  # Whirlpool rhash
  echo "  Whirlpool rhash..."
  v=$(measure_avg_seconds whirlpool "$file" "$RHASH" "$size")
  whirlpool_rhash_vals+=("$v")
  echo "	-> $v s"
done

# cleanup files
rm -rf "$TMPDIR"

# helper to join array with commas
join_commas() {
  local IFS=,
  printf '%s' "$*"
}

# prepare JS arrays
labels_js=$(printf '"%s",' "${labels[@]}")
labels_js="[${labels_js%,}]"

md5ft_js=$(printf '%s,' "${md5_ft_vals[@]}")
md5ft_js="[${md5ft_js%,}]"

md5ssl_js=$(printf '%s,' "${md5_ssl_vals[@]}")
md5ssl_js="[${md5ssl_js%,}]"

shaft_js=$(printf '%s,' "${sha_ft_vals[@]}")
shaft_js="[${shaft_js%,}]"

shassl_js=$(printf '%s,' "${sha_ssl_vals[@]}")
shassl_js="[${shassl_js%,}]"

whirlpoolft_js=$(printf '%s,' "${whirlpool_ft_vals[@]}")
whirlpoolft_js="[${whirlpoolft_js%,}]"

whirlpoolrhash_js=$(printf '%s,' "${whirlpool_rhash_vals[@]}")
whirlpoolrhash_js="[${whirlpoolrhash_js%,}]"

# generate HTML
cat > "$OUTPUT" <<EOF
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>ft_ssl Benchmark</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{font-family:Arial;background:#111;color:#fff;padding:20px}
canvas{background:#fff;border-radius:8px;display:block;margin:20px auto}
.legend{position:fixed;top:12px;right:12px;background:#222;padding:8px;border-radius:6px}
.box{width:12px;height:12px;display:inline-block;margin-right:8px}
.small{font-size:12px;color:#ccc}
</style>
</head>
<body>
<h1 style="text-align:center">ft_ssl vs OpenSSL/rhash — MD5, SHA256 & Whirlpool</h1>
<div class="legend">
  <div><span class="box" style="background:#4CAF50"></span><span class="small">ft_ssl</span></div>
  <div><span class="box" style="background:#F44336"></span><span class="small">OpenSSL/rhash</span></div>
</div>

<canvas id="md5" width="900" height="400"></canvas>
<canvas id="sha" width="900" height="400"></canvas>
<canvas id="whirlpool" width="900" height="400"></canvas>

<script>
const labels = $labels_js;
const md5_ft = $md5ft_js;
const md5_ssl = $md5ssl_js;
const sha_ft = $shaft_js;
const sha_ssl = $shassl_js;
const whirlpool_ft = $whirlpoolft_js;
const whirlpool_rhash = $whirlpoolrhash_js;

// draw function (time in seconds)
function draw(id, title, a1, a2, label1 = 'ft_ssl', label2 = 'OpenSSL') {
  new Chart(document.getElementById(id), {
	type: 'line',
	data: {
	  labels: labels,
	  datasets: [
		{ label: label1, data: a1, borderColor: '#4CAF50', fill:false, tension:0.1 },
		{ label: label2, data: a2, borderColor: '#F44336', fill:false, tension:0.1 },
	  ]
	},
	options: {
	  plugins: { title: { display:true, text: title } },
	  scales: {
		x: { 
		  title: { display:true, text:'File size (bytes)' }, 
		  type:'linear',
		  ticks: { callback: function(v) { return v.toExponential(); } }
		},
		y: { title: { display:true, text:'Time (s)' } }
	  }
	}
  });
}

draw('md5', 'MD5 — average (warmup ignored)', md5_ft, md5_ssl);
draw('sha', 'SHA256 — average (warmup ignored)', sha_ft, sha_ssl);
draw('whirlpool', 'Whirlpool — average (warmup ignored)', whirlpool_ft, whirlpool_rhash, 'ft_ssl', 'rhash');
</script>
</body>
</html>
EOF

echo "Done -> $OUTPUT"
