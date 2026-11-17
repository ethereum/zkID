#!/bin/bash

usage() {
  echo "Usage: $0 {jwt|jwt_1k|jwt_2k|jwt_4k|jwt_8k|show|show_mdoc|ecdsa|mdoc|all}"
  echo "  jwt:    Compile the default JWT circuit."
  echo "  jwt_1k: Compile JWT circuit (1KB - maxMsg=1280)."
  echo "  jwt_2k: Compile JWT circuit (2KB - maxMsg=2048)."
  echo "  jwt_4k: Compile JWT circuit (4KB - maxMsg=4096)."
  echo "  jwt_8k: Compile JWT circuit (8KB - maxMsg=8192)."
  echo "  show:   Compile Show circuit (with revocation)."
  echo "  show_mdoc: Compile Show circuit without revocation (MDOC flow)."
  echo "  ecdsa:  Compile ECDSA circuit."
  echo "  mdoc:   Compile MDOC circuit."
  echo "  all:    Compile everything: jwt + jwt_1k/2k/4k/8k + show + show_mdoc + ecdsa + mdoc."
  exit 1
}

if [ -z "$1" ]; then
  echo "Error: No option provided."
  usage
fi

# Generic compile function for any named circuit
compile_circuit() {
  local name="$1"
  echo "Compiling circuit: $name"
  npx circomkit compile "$name" || { echo "Error: Failed to compile $name."; exit 1; }
  cd "build/$name/" || { echo "Error: 'build/$name/' directory not found."; exit 1; }
  cp "$name.r1cs" "${name}_js/" || { echo "Error: Failed to copy $name.r1cs."; exit 1; }
  cd ../.. || exit 1
  mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
  # Always overwrite so build/cpp/ stays in sync with the freshly compiled circuit.
  # (This used to be guarded with `[ ! -f ... ]`, which silently kept stale copies
  # whenever a circuit was recompiled — leaving downstream consumers like
  # ecdsa-spartan2/build.rs linked against an outdated witness generator.)
  cp "build/$name/${name}_cpp/$name.cpp" build/cpp/ || { echo "Error: Failed to copy $name.cpp."; exit 1; }
  cp "build/$name/${name}_cpp/$name.dat" build/cpp/ || { echo "Error: Failed to copy $name.dat."; exit 1; }
  echo "$name compilation complete."
}

case "$1" in
  jwt|jwt_1k|jwt_2k|jwt_4k|jwt_8k|show|show_mdoc|ecdsa|mdoc)
    compile_circuit "$1"
    ;;
  all)
    echo "Compiling all circuits (jwt + jwt_1k/2k/4k/8k + show + show_mdoc + ecdsa + mdoc)..."
    compile_circuit jwt
    compile_circuit jwt_1k
    compile_circuit jwt_2k
    compile_circuit jwt_4k
    compile_circuit jwt_8k
    compile_circuit show
    compile_circuit show_mdoc
    compile_circuit ecdsa
    compile_circuit mdoc
    echo "All circuits compiled successfully."
    ;;
  *)
    echo "Error: Invalid option '$1'."
    usage
    ;;
esac
