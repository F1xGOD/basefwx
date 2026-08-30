# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Lesser General Public License v3.0 or later.

"""Owned subprocess pairs used by streaming media transforms."""

from __future__ import annotations

from ._media_shared import basefwx


_STDERR_TAIL_LIMIT = 1 << 20
_STDERR_READ_SIZE = 64 << 10


class _BoundedStderrCapture:
    """Drain a process stderr pipe without allowing unbounded memory growth."""

    def __init__(self, process: "basefwx.subprocess.Popen[bytes]") -> None:
        self._stream = process.stderr
        self._tail = bytearray()
        self._thread = None
        if self._stream is not None:
            self._thread = basefwx.threading.Thread(
                target=self._drain,
                name="basefwx-stderr-drain",
                daemon=True,
            )
            self._thread.start()

    def _drain(self) -> None:
        try:
            while True:
                chunk = self._stream.read(_STDERR_READ_SIZE)
                if not chunk:
                    return
                if len(chunk) >= _STDERR_TAIL_LIMIT:
                    self._tail[:] = chunk[-_STDERR_TAIL_LIMIT:]
                    continue
                overflow = len(self._tail) + len(chunk) - _STDERR_TAIL_LIMIT
                if overflow > 0:
                    del self._tail[:overflow]
                self._tail.extend(chunk)
        except (OSError, ValueError):
            return

    def text(self) -> str:
        if self._thread is not None:
            self._thread.join()
        return bytes(self._tail).decode("utf-8", "replace")

    def close(self) -> None:
        if self._stream is not None:
            with basefwx.contextlib.suppress(OSError, ValueError):
                self._stream.close()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=1.0)


class _VideoProcessPipeline:
    """Own decoder/encoder processes and their stderr drainers."""

    def __init__(self, decode_cmd: "list[str]", encode_cmd: "list[str]") -> None:
        self.decoder = None
        self.encoder = None
        self._decoder_stderr = None
        self._encoder_stderr = None
        self._decoder_error = ""
        self._encoder_error = ""
        try:
            self.decoder = basefwx.subprocess.Popen(
                [str(part) for part in decode_cmd],
                stdout=basefwx.subprocess.PIPE,
                stderr=basefwx.subprocess.PIPE,
            )
            self._decoder_stderr = _BoundedStderrCapture(self.decoder)
            self.encoder = basefwx.subprocess.Popen(
                [str(part) for part in encode_cmd],
                stdin=basefwx.subprocess.PIPE,
                stderr=basefwx.subprocess.PIPE,
            )
            self._encoder_stderr = _BoundedStderrCapture(self.encoder)
        except BaseException:
            self.close()
            raise

    @property
    def decoder_error(self) -> str:
        return self._decoder_error

    @property
    def encoder_error(self) -> str:
        return self._encoder_error

    def wait_encoder(self) -> int:
        if self.encoder is None:
            raise RuntimeError("ffmpeg encoder process is unavailable")
        return_code = self.encoder.wait()
        self._encoder_error = self._capture_text(self._encoder_stderr)
        return return_code

    def wait(self) -> "tuple[int, int]":
        if self.decoder is None or self.encoder is None:
            raise RuntimeError("ffmpeg process pipeline is incomplete")
        decoder_code = self.decoder.wait()
        encoder_code = self.encoder.wait()
        self._decoder_error = self._capture_text(self._decoder_stderr)
        self._encoder_error = self._capture_text(self._encoder_stderr)
        return decoder_code, encoder_code

    @staticmethod
    def _capture_text(capture: "_BoundedStderrCapture | None") -> str:
        return capture.text() if capture is not None else ""

    @staticmethod
    def _close_pipe(pipe) -> None:
        if pipe is not None:
            with basefwx.contextlib.suppress(OSError, ValueError):
                pipe.close()

    @staticmethod
    def _stop_process(process) -> None:
        if process is None or process.poll() is not None:
            return
        with basefwx.contextlib.suppress(OSError):
            process.terminate()
        try:
            process.wait(timeout=1.0)
            return
        except basefwx.subprocess.TimeoutExpired:
            with basefwx.contextlib.suppress(OSError):
                process.kill()
        with basefwx.contextlib.suppress(
            OSError,
            basefwx.subprocess.TimeoutExpired,
        ):
            process.wait(timeout=1.0)

    def close(self) -> None:
        if self.encoder is not None:
            self._close_pipe(self.encoder.stdin)
        if self.decoder is not None:
            self._close_pipe(self.decoder.stdout)
        self._stop_process(self.encoder)
        self._stop_process(self.decoder)
        if self._decoder_stderr is not None:
            self._decoder_stderr.close()
        if self._encoder_stderr is not None:
            self._encoder_stderr.close()
