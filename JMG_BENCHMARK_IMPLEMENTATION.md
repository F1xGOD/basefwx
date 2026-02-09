# jMG Benchmarking Implementation Summary

## Overview
Implemented comprehensive jMG (media cipher) benchmarking across all languages (Python, PyPy, C++, Java) to ensure proper performance monitoring and fair cross-language comparison of media encryption/decryption operations.

## Changes Made

### 1. Test Media Generation (`scripts/generate_test_media.py`)
- Created Python script to generate synthetic test media using FFmpeg
- Generates three test files:
  - **jmg_sample.png** (323 B): Noisy PNG image
  - **jmg_sample.mp4** (6.4 KB): 3-second noisy MP4 video
  - **jmg_sample.m4a** (1.9 KB): 3-second noisy audio file
- Files are small for quick benchmark runs while representative of real media

### 2. Python Benchmark Support (`scripts/test_all.sh` - py_helper)
Added `cmd_bench_jmg()` function:
- Supports both single-threaded and parallel (multi-worker) benchmarking
- Uses tempfile for transparent encryption/decryption
- Measures roundtrip time (encrypt + decrypt)
- Follows same `_bench()` pattern as other benchmarks
- Integrates with BASEFWX_BENCH_WARMUP, BASEFWX_BENCH_ITERS, BASEFWX_BENCH_WORKERS

### 3. Java CLI Support (`java/src/main/java/com/fixcraft/basefwx/cli/BaseFwxCli.java`)
Added `bench-jmg` command:
- **Command**: `java -jar basefwx-java.jar bench-jmg <media> <password> [--no-master]`
- Supports parallel benchmarking with worker threads
- Creates per-worker temp directories for isolation
- Measures median of roundtrip (encrypt + decrypt) times
- Compatible with JIT warmup iterations
- Usage documented in `usage()` method

### 4. C++ CLI Support (`cpp/src/main.cpp`)
Added `bench-jmg` command:
- **Command**: `./basefwx_cpp bench-jmg <media> <password> [--no-master] [--master-pub <path>]`
- Parallel benchmark support matching b512file pattern
- Generates unique temp directories per worker
- Measures median roundtrip time with exclusive access
- Uses atomic operations for thread-safe sink updates
- Usage documented in `PrintUsage()` function

### 5. Benchmark Integration (`scripts/test_all.sh`)
Added jMG benchmarks to PHASE4:
- **Python**: Loops through `JMG_CASES` array with `bench-jmg` command
- **PyPy**: Same as Python with PyPy interpreter
- **C++**: Uses `bench-jmg` command with C++ binary
- **Java**: Uses `bench-jmg` command with Java CLI and appropriate JVM flags
- Uses standard warmup/iters/workers configuration
- Results tagged as: `jmg_<lang>_<mediatype>` (e.g., `jmg_cpp_sample`, `jmg_java_mp4`)

## Technical Details

### Media Benchmarking Pattern
```bash
# For each media file in JMG_CASES:
for jmg_file in "${JMG_CASES[@]}"; do
    time_cmd_bench "jmg_<lang>_${jmg_file%.*}" \
        env WARMUP="..." ITERS="..." \
        <command> bench-jmg "$ORIG_DIR/$jmg_file" "$PW"
done
```

### Benchmark Warmup Handling
- jMG benchmarks use standard `BENCH_WARMUP_FILE` (1-3 iterations based on test mode)
- Java gets additional warmup via class loader warm-up (pre-compiled paths)
- Parallel workers coordinate through process/thread pool mechanism

### Performance Considerations
- Small media files (~7 KB total) enable fast benchmark cycles
- Roundtrip (encrypt-decrypt) ensures crypto operations are exercised
- Parallel benchmarks isolate per-worker files to prevent I/O contention
- Temp directories cleaned up after benchmark completion

## Validation

### Files Modified
- ✅ `scripts/generate_test_media.py` - New media generator
- ✅ `scripts/test_all.sh` - Python helper + benchmark integration
- ✅ `java/src/main/java/com/fixcraft/basefwx/cli/BaseFwxCli.java` - Java CLI
- ✅ `cpp/src/main.cpp` - C++ CLI

### Files Generated
- ✅ `jmg_sample.png` - 323 B
- ✅ `jmg_sample.mp4` - 6.4 KB
- ✅ `jmg_sample.m4a` - 1.9 KB

### Test Coverage
- ✅ Python single & parallel
- ✅ PyPy single & parallel
- ✅ C++ single & parallel
- ✅ Java single & parallel with JIT warmup

## Benchmark Output
Benchmarks produce standard `BENCH_NS=<nanoseconds>` output for comparison tool integration
Results tagged: `jmg_<lang>_<media_type>` for easy identification in reports

## Future Improvements (Optional)
- Add larger media test files (10MB+) for throughput benchmarking
- Implement streaming benchmarks (no temp file buffer)
- Add codec-specific benchmarks (H.264 vs VP9 vs HEVC)
- Compare pre/post-optimization performance
