#!/usr/bin/env python3
"""
Generate synthetic test media for jMG benchmarking.
Requires FFmpeg to be installed.
"""
import os
import subprocess
import sys
from pathlib import Path

def run_cmd(cmd, check=True):
    """Run a shell command."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Command failed: {cmd}", file=sys.stderr)
        print(f"stderr: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result

def check_ffmpeg():
    """Check if ffmpeg and ffprobe are available."""
    result_ffmpeg = subprocess.run(["ffmpeg", "-version"], capture_output=True)
    result_ffprobe = subprocess.run(["ffprobe", "-version"], capture_output=True)
    
    if result_ffmpeg.returncode != 0:
        print("ERROR: ffmpeg not found. Install it with: apt-get install ffmpeg", file=sys.stderr)
        return False
    if result_ffprobe.returncode != 0:
        print("ERROR: ffprobe not found. Install it with: apt-get install ffmpeg", file=sys.stderr)
        return False
    return True

def generate_png(output_path, width=320, height=240, duration_ms=100):
    """Generate a noisy PNG image."""
    print(f"Generating noisy PNG: {output_path}")
    # Generate a single noisy frame
    cmd = f'ffmpeg -f lavfi -i "color=black:s={width}x{height}:d=0.1" -vf "noise=alls=0.5" -pix_fmt yuv420p -vframes 1 {output_path} -y 2>/dev/null'
    run_cmd(cmd)
    print(f"  ✓ {output_path}")

def generate_mp4(output_path, width=320, height=240, duration_sec=5):
    """Generate a noisy MP4 video."""
    print(f"Generating noisy MP4: {output_path} ({duration_sec}s)")
    # Generate noise video with basic audio
    cmd = f'ffmpeg -f lavfi -i "color=black:s={width}x{height}:d={duration_sec}" -f lavfi -i "anullsrc=r=44100:cl=mono:d={duration_sec}" -vf "noise=alls=0.5" -pix_fmt yuv420p {output_path} -y 2>/dev/null'
    run_cmd(cmd)
    print(f"  ✓ {output_path}")

def generate_m4a(output_path, duration_sec=5):
    """Generate a noisy M4A audio file."""
    print(f"Generating noisy M4A: {output_path} ({duration_sec}s)")
    # Generate white noise using anullsrc with filter
    cmd = f'ffmpeg -f lavfi -i "anullsrc=r=44100:cl=mono:d={duration_sec}" -af "highpass=f=200" -c:a aac -b:a 128k {output_path} -y 2>/dev/null'
    run_cmd(cmd)
    print(f"  ✓ {output_path}")

def main():
    if not check_ffmpeg():
        return 1
    
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    media_files = [
        (project_root / "jmg_sample.png", "generate_png", {}),
        (project_root / "jmg_sample.mp4", "generate_mp4", {"duration_sec": 3}),
        (project_root / "jmg_sample.m4a", "generate_m4a", {"duration_sec": 3}),
    ]
    
    print("Generating test media for jMG benchmarking...")
    for output_path, gen_func, kwargs in media_files:
        if output_path.exists():
            print(f"Skipping {output_path.name} (already exists)")
            continue
        
        if gen_func == "generate_png":
            generate_png(str(output_path), **kwargs)
        elif gen_func == "generate_mp4":
            generate_mp4(str(output_path), **kwargs)
        elif gen_func == "generate_m4a":
            generate_m4a(str(output_path), **kwargs)
    
    # Verify files
    print("\nVerifying generated media files:")
    for output_path, _, _ in media_files:
        if output_path.exists():
            size_kb = output_path.stat().st_size / 1024
            print(f"  ✓ {output_path.name}: {size_kb:.1f} KB")
        else:
            print(f"  ✗ {output_path.name}: NOT FOUND", file=sys.stderr)
            return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
