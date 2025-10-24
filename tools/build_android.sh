#!/bin/bash
# SPDX-License-Identifier: MIT

# Build all targets for Android for convenient testing on a device
# Set ANDROID_NDK_ROOT to be an NDK directory (via Android SDK tools)

set -eux


export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang
export PKG_CONFIG_SYSROOT_DIR=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/sysroot

cargo build --release --all-targets --target aarch64-linux-android
