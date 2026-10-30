#!/bin/bash
set -euo pipefail

QEMU="qemu-system-aarch64"
KERNEL="./android14-6.1-deprecated"
ROOTFS="./buildroot-2025.05.1/output/images/rootfs.ext2"

# Sanity checks
if [ ! -f "$KERNEL/arch/arm64/boot/Image" ]; then
  echo "ERROR: kernel not found: $KERNEL/arch/arm64/boot/Image" >&2
  exit 1
fi
if [ ! -f "$ROOTFS" ]; then
  echo "ERROR: rootfs not found: $ROOTFS" >&2
  exit 1
fi

# Build QEMU args one-by-one using an array
ARGS=()

# Core machine setup
ARGS+=("-cpu" "cortex-a53")
ARGS+=("-machine" "virt")
ARGS+=("-nographic")
ARGS+=("-smp" "4")
ARGS+=("-m" "2048")

# Kernel & rootfs
ARGS+=("-kernel" "$KERNEL/arch/arm64/boot/Image")
ARGS+=("-drive" "file=$ROOTFS,format=raw,if=virtio")

# Networking (user mode + SSH forward)
ARGS+=("-netdev" "user,id=net0,hostfwd=tcp::13337-:22")
ARGS+=("-device" "virtio-net-device,netdev=net0")

# Default kernel command line parameters
CMDLINE="console=ttyAMA0 root=/dev/vda"

# Optional flags processing
for opt in "$@"; do
  case "$opt" in
    debug)
      ARGS+=("-s")  # Wait for gdb connection on localhost:1234
      CMDLINE="$CMDLINE nokaslr"  # Append nokaslr only when debugging
      ;;
    freeze)
      ARGS+=("-S")  # Start paused
      ;;
    *)
      echo "Warning: unknown option '$opt' (supported: debug, freeze)" >&2
      ;;
  esac
done

# Pass final kernel command line string
ARGS+=("-append" "$CMDLINE")

# Show full command for debugging
echo "Running: $QEMU ${ARGS[*]}"

# Run QEMU
exec "$QEMU" "${ARGS[@]}"
