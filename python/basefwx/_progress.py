# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations


class _LazyEngine:
    """Resolve basefwx attributes after legacy finishes loading."""

    def __getattr__(self, name: str):
        from .legacy import basefwx as _engine
        return getattr(_engine, name)


basefwx = _LazyEngine()

class _ProgressReporter:
    """Lightweight textual progress reporter with two WinRAR-style bars."""

    def __init__(self, total_files: int, stream=None, min_interval: float=0.1):
        self.total_files = max(total_files, 1)
        self.stream = stream or basefwx.sys.stdout
        self._printed = False
        self._min_interval = max(0.0, float(min_interval))
        self._is_tty = bool(getattr(self.stream, 'isatty', lambda: False)())
        self._last_render = 0.0
        self._last_fraction: dict[int, float] = {}
        self._lock = basefwx.threading.Lock()
        self._telemetry_last = 0.0
        self._telemetry_text = ''
        self._telemetry_interval = 5.0
        self._telemetry_enabled = True
        self._telemetry_expect_gpu = False
        try:
            raw_telemetry = basefwx.os.getenv('BASEFWX_PROGRESS_TELEMETRY', '1').strip().lower()
            if raw_telemetry in {'0', 'false', 'no', 'off'}:
                self._telemetry_enabled = False
        except Exception:
            pass
        try:
            import shutil
            self._term_width = shutil.get_terminal_size().columns
        except Exception:
            self._term_width = 80
        try:
            import psutil
            self._psutil = psutil
        except Exception:
            self._psutil = None
        self._cpu_stat_prev_total: 'basefwx.typing.Optional[int]' = None
        self._cpu_stat_prev_idle: 'basefwx.typing.Optional[int]' = None
        if self._psutil is None:
            with basefwx.contextlib.suppress(Exception):
                self._probe_cpu_percent_fallback()
        try:
            import colorama
            self._has_colors = True
            self._green = colorama.Fore.GREEN
            self._reset = colorama.Fore.RESET
        except ImportError:
            self._has_colors = False
            self._green = ''
            self._reset = ''
        term = basefwx.os.getenv('TERM')
        self._supports_ansi = self._is_tty and (basefwx.os.name != 'nt' or self._has_colors or basefwx.os.getenv('WT_SESSION') or basefwx.os.getenv('ANSICON') or (term and term != 'dumb'))
        self._has_nvidia_smi = bool(basefwx.shutil.which('nvidia-smi'))

    def _ansi(self, text: str, code: str) -> str:
        if not self._supports_ansi:
            return text
        return f'\x1b[{code}m{text}\x1b[0m'

    def _color_label(self, label: str) -> str:
        if label == 'CPU':
            return self._ansi(label, '36;1')
        if label == 'GPU':
            return self._ansi(label, '35;1')
        if label == 'RAM':
            return self._ansi(label, '32;1')
        return self._ansi(label, '1')

    def _color_temp(self, temp_c: float) -> str:
        value = f'{temp_c:.0f}C'
        if temp_c <= 19.0:
            color = '94'
        elif temp_c <= 37.0:
            color = '32'
        elif temp_c <= 67.0:
            color = '33'
        elif temp_c <= 85.0:
            color = '38;5;208'
        elif temp_c <= 100.0:
            color = '31'
        else:
            color = '91'
        return self._ansi(value, color)

    def set_hw_execution_plan(self, plan: 'basefwx.typing.Optional[dict[str, basefwx.typing.Any]]') -> None:
        expect_gpu = False
        if isinstance(plan, dict):
            for key in ('selected_accel', 'encode_device', 'decode_device', 'pixel_backend'):
                raw = str(plan.get(key, '') or '').strip().lower()
                if raw and raw not in {'cpu', 'none', 'off', 'false', '0'}:
                    expect_gpu = True
                    break
        with self._lock:
            self._telemetry_expect_gpu = expect_gpu
            self._telemetry_last = 0.0
            self._telemetry_text = ''

    def _safe_float(self, value) -> float | None:
        try:
            return float(value)
        except Exception:
            return None

    def _probe_cpu_percent_fallback(self) -> float | None:
        if not basefwx.sys.platform.startswith('linux'):
            return None
        try:
            with open('/proc/stat', 'r', encoding='utf-8', errors='ignore') as handle:
                first = handle.readline().strip()
            if not first.startswith('cpu '):
                return None
            fields = [int(part) for part in first.split()[1:] if part.isdigit()]
            if len(fields) < 4:
                return None
            total = int(sum(fields))
            idle = int(fields[3] + (fields[4] if len(fields) > 4 else 0))
            prev_total = self._cpu_stat_prev_total
            prev_idle = self._cpu_stat_prev_idle
            self._cpu_stat_prev_total = total
            self._cpu_stat_prev_idle = idle
            if prev_total is None or prev_idle is None:
                return None
            delta_total = total - prev_total
            delta_idle = idle - prev_idle
            if delta_total <= 0:
                return None
            usage = 100.0 * (1.0 - delta_idle / float(delta_total))
            return max(0.0, min(100.0, usage))
        except Exception:
            return None

    def _probe_ram_percent_fallback(self) -> float | None:
        if not basefwx.sys.platform.startswith('linux'):
            return None
        try:
            mem_total_kib = None
            mem_avail_kib = None
            with open('/proc/meminfo', 'r', encoding='utf-8', errors='ignore') as handle:
                for line in handle:
                    if line.startswith('MemTotal:'):
                        parts = line.split()
                        if len(parts) >= 2:
                            mem_total_kib = int(parts[1])
                    elif line.startswith('MemAvailable:'):
                        parts = line.split()
                        if len(parts) >= 2:
                            mem_avail_kib = int(parts[1])
                    if mem_total_kib is not None and mem_avail_kib is not None:
                        break
            if not mem_total_kib or mem_avail_kib is None:
                return None
            used = max(0, mem_total_kib - mem_avail_kib)
            return max(0.0, min(100.0, used * 100.0 / float(mem_total_kib)))
        except Exception:
            return None

    def _probe_nvidia_metrics(self) -> 'tuple[float | None, float | None]':
        if not self._has_nvidia_smi:
            return (None, None)
        try:
            result = basefwx.subprocess.run(['nvidia-smi', '--query-gpu=utilization.gpu,temperature.gpu', '--format=csv,noheader,nounits'], capture_output=True, text=True)
            if result.returncode != 0:
                return (None, None)
            gpu_values = []
            temp_values = []
            for line in (result.stdout or '').splitlines():
                parts = [p.strip() for p in line.split(',')]
                if len(parts) < 2:
                    continue
                gpu_val = self._safe_float(parts[0])
                temp_val = self._safe_float(parts[1])
                if gpu_val is not None:
                    gpu_values.append(gpu_val)
                if temp_val is not None and temp_val > 0:
                    temp_values.append(temp_val)
            gpu_pct = sum(gpu_values) / len(gpu_values) if gpu_values else None
            gpu_temp = sum(temp_values) / len(temp_values) if temp_values else None
            return (gpu_pct, gpu_temp)
        except Exception:
            return (None, None)

    def _probe_cpu_temp(self) -> float | None:
        if self._psutil is not None:
            try:
                sensors = self._psutil.sensors_temperatures()
            except Exception:
                sensors = {}
            if sensors:
                values = []
                for entries in sensors.values():
                    for entry in entries:
                        current = self._safe_float(getattr(entry, 'current', None))
                        if current is not None and current > 0:
                            values.append(current)
                if values:
                    return sum(values) / len(values)
        if not basefwx.sys.platform.startswith('linux'):
            return None
        values: 'list[float]' = []
        try:
            thermal_root = basefwx.pathlib.Path('/sys/class/thermal')
            for temp_file in thermal_root.glob('thermal_zone*/temp'):
                try:
                    raw = temp_file.read_text(encoding='utf-8', errors='ignore').strip()
                    if not raw:
                        continue
                    val = float(raw)
                    if val > 1000.0:
                        val /= 1000.0
                    if 5.0 <= val <= 130.0:
                        values.append(val)
                except Exception:
                    continue
        except Exception:
            return None
        if not values:
            return None
        return sum(values) / len(values)

    def _sample_runtime_metrics(self) -> str:
        if not self._telemetry_enabled:
            return ''
        cpu_pct = None
        ram_pct = None
        if self._psutil is not None:
            try:
                cpu_pct = self._safe_float(self._psutil.cpu_percent(interval=None))
            except Exception:
                cpu_pct = None
            try:
                ram_pct = self._safe_float(self._psutil.virtual_memory().percent)
            except Exception:
                ram_pct = None
        else:
            cpu_pct = self._probe_cpu_percent_fallback()
            ram_pct = self._probe_ram_percent_fallback()
        if cpu_pct is None:
            cpu_pct = 0.0
        gpu_pct = None
        gpu_temp = None
        if self._telemetry_expect_gpu:
            gpu_pct, gpu_temp = self._probe_nvidia_metrics()
        cpu_temp = self._probe_cpu_temp()
        temp_values = [v for v in (cpu_temp, gpu_temp) if v is not None]
        temp_avg = sum(temp_values) / len(temp_values) if temp_values else None
        parts: list[str] = []
        if cpu_pct is not None:
            parts.append(f"{self._color_label('CPU')} {cpu_pct:.0f}%")
        if gpu_pct is not None and gpu_pct > 0.5:
            parts.append(f"{self._color_label('GPU')} {gpu_pct:.0f}%")
        if ram_pct is not None:
            parts.append(f"{self._color_label('RAM')} {ram_pct:.0f}%")
        if temp_avg is not None:
            parts.append(self._color_temp(temp_avg))
        if not parts:
            return ''
        return ' \\ '.join(parts)

    def _telemetry_snapshot(self, force: bool=False) -> str:
        if not self._telemetry_enabled:
            return ''
        now = basefwx.time.monotonic()
        if force or not self._telemetry_text or now - self._telemetry_last >= self._telemetry_interval:
            self._telemetry_text = self._sample_runtime_metrics()
            self._telemetry_last = now
        return self._telemetry_text

    def reset_terminal_state(self):
        """Ensure terminal is in a clean state for subsequent output"""
        with self._lock:
            if self._printed:
                try:
                    self.stream.write('\n')
                    self.stream.flush()
                except Exception:
                    print()
            self._printed = False

    def _render_bar(self, fraction: float, width: int | None=None) -> str:
        width = width or basefwx.PROGRESS_BAR_WIDTH
        fraction = max(0.0, min(1.0, fraction))
        filled = int(fraction * width)
        if filled >= width and fraction >= 1.0:
            bar = '❚' * width
            if self._has_colors:
                return f"({self._green}{'❚' * width}{self._reset})"
            return f"({'❚' * width})"
        else:
            filled_part = '❚' * filled
            empty_part = ' ' * (width - filled)
            return f'({filled_part}{empty_part})'

    @staticmethod
    def _format_size_hint(size_hint: 'basefwx.typing.Tuple[int, int]') -> str:
        src, dst = size_hint
        return f'{basefwx._human_readable_size(src)} -> {basefwx._human_readable_size(dst)}'

    def _write(self, line1: str, line2: str, force: bool=False) -> None:
        now = basefwx.time.monotonic()
        if not force and self._printed and (now - self._last_render < self._min_interval):
            return
        max_width = self._term_width
        if len(line1) > max_width:
            tail_keep = min(36, max(0, max_width // 2))
            head_keep = max(0, max_width - tail_keep - 1)
            if head_keep > 0 and tail_keep > 0:
                line1 = line1[:head_keep] + '…' + line1[-tail_keep:]
            else:
                line1 = line1[:max_width]
        if len(line2) > max_width:
            parts = line2.split('[')
            if len(parts) > 1:
                prefix = parts[0]
                rest = '[' + '['.join(parts[1:])
                filename_parts = rest.split(']', 1)
                if len(filename_parts) > 1:
                    filename = filename_parts[0] + ']'
                    suffix = filename_parts[1] if len(filename_parts) > 1 else ''
                    avail_prefix_space = max(10, max_width - len(filename) - len(suffix) - 5)
                    if len(prefix) > avail_prefix_space:
                        prefix = prefix[:avail_prefix_space]
                    line2 = prefix + filename + suffix
                    if len(line2) > max_width:
                        line2 = line2[:max_width]
                else:
                    line2 = line2[:max_width]
            else:
                line2 = line2[:max_width]
        if self._is_tty and self._supports_ansi:
            if self._printed:
                self.stream.write('\x1b[1A\r')
            else:
                self.stream.write('\r\x1b[2K')
            self.stream.write('\r\x1b[2K')
            self.stream.write(line1)
            self.stream.write('\n')
            self.stream.write('\r\x1b[2K')
            self.stream.write(line2)
            self.stream.flush()
        elif self._is_tty:
            if not self._printed:
                try:
                    self.stream.write('\r')
                    self.stream.write(' ' * self._term_width)
                    self.stream.write('\r')
                except Exception:
                    pass
            try:
                self.stream.write(line1 + '\n')
                self.stream.write(line2)
                self.stream.flush()
            except Exception:
                print(line1)
                print(line2, end='')
        elif not self._printed or force:
            try:
                self.stream.write(line1 + '\n')
                self.stream.write(line2 + '\n')
                self.stream.flush()
            except Exception:
                print(line1)
                print(line2)
        self._printed = True
        self._last_render = now

    def update(self, file_index: int, fraction: float, phase: str, path: 'basefwx.pathlib.Path', *, size_hint: 'basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]'=None) -> None:
        fraction = max(0.0, min(1.0, float(fraction)))
        with self._lock:
            self._last_fraction[file_index] = fraction
            overall_fraction = sum(self._last_fraction.values()) / self.total_files
            overall = self._render_bar(overall_fraction)
            current = self._render_bar(fraction)
            completed_files = sum((1 for frac in self._last_fraction.values() if frac >= 1.0))
            label = path.name if path else ''
            if self.total_files == 1:
                if fraction < 0.1:
                    status_text = f'processing {label}' if label else 'processing'
                elif fraction < 1.0:
                    status_text = f'{phase} {label}' if label else phase
                else:
                    status_text = 'complete'
            elif fraction < 1.0:
                status_text = f'{completed_files} complete, processing {label}' if label else f'{completed_files} complete'
            else:
                status_text = f'{completed_files}/{self.total_files} files'
            percent_overall = f'{overall_fraction * 100:3.0f}%'
            percent_file = f'{fraction * 100:3.0f}%'
            hint_text = f' ({self._format_size_hint(size_hint)})' if size_hint else ''
            label_text = f' [{label}]' if label else ''
            force = fraction >= 1.0 or overall_fraction >= 1.0
            telemetry_text = self._telemetry_snapshot(force=force)
            telemetry_suffix = f' | {telemetry_text}' if telemetry_text else ''
            line1 = f'Overall {overall} {percent_overall} {status_text}{telemetry_suffix}'
            line2 = f'File    {current} {percent_file} phase: {phase}{hint_text}{label_text}'
            line1 = line1.replace('\n', ' ')
            line2 = line2.replace('\n', ' ')
            self._write(line1, line2, force=force)

    def finalize_file(self, file_index: int, path: 'basefwx.pathlib.Path', *, size_hint: 'basefwx.typing.Optional[basefwx.typing.Tuple[int, int]]'=None) -> None:
        with self._lock:
            self._last_fraction[file_index] = 1.0
            overall_fraction = sum(self._last_fraction.values()) / self.total_files
            overall = self._render_bar(overall_fraction)
            label = path.name if path else ''
            current = self._render_bar(1.0)
            percent_overall = f'{overall_fraction * 100:3.0f}%'
            status_text = f'{sum((1 for frac in self._last_fraction.values() if frac >= 1.0))}/{self.total_files} files'
            hint_text = f' ({self._format_size_hint(size_hint)})' if size_hint else ''
            label_text = f' [{label}]' if label else ''
            telemetry_text = self._telemetry_snapshot(force=True)
            telemetry_suffix = f' | {telemetry_text}' if telemetry_text else ''
            completion_indicator = f' {self._green}✓{self._reset}' if self._has_colors else ' ✓'
            line1 = f'Overall {overall} {percent_overall} {status_text}{telemetry_suffix}'
            line2 = f'File    {current} 100% phase: done{hint_text}{label_text}{completion_indicator}'
            self._write(line1, line2, force=True)
            try:
                self.stream.write('\n')
                self.stream.flush()
            except Exception:
                print()
            self._printed = False
