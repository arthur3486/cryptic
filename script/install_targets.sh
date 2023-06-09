#!/bin/sh

targets=(
  "x86_64-unknown-linux-gnu"
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
  "x86_64-pc-windows-gnu"
)

for t in "${targets[@]}"; 
do
  echo "Adding a platform target: $t"

  rustup target add $t
done