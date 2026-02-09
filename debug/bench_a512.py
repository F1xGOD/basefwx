#!/usr/bin/env python3
"""Quick a512 benchmark comparison - direct timing only"""
import time
import sys


TEXT = "Hello World Testing Performance Benchmark" * 100


def bench_python():
    """Benchmark Python implementation"""
    import basefwx
    
    start = time.perf_counter()
    for _ in range(1000):
        result = basefwx.a512encode(TEXT)
    elapsed = time.perf_counter() - start
    return elapsed, result


def main():
    print("Benchmarking a512 encode (1000 iterations)...")
    print(f"Input size: {len(TEXT)} chars\n")
    
    # Python benchmark
    print("Python ...")
    py_time, py_result = bench_python()
    print(f"  Time: {py_time:.3f}s ({py_time/1000*1000:.2f} ms/op)")
    print(f"  Output sample: {py_result[:60]}...")
    
    print("\n✅ Python benchmark complete")
    print(f"Run C++ benchmark separately with:")
    print(f'  time (for i in {{1..1000}}; do ./cpp/build/basefwx_cpp a512-enc "{TEXT[:50]}" > /dev/null; done)')


if __name__ == '__main__':
    main()
