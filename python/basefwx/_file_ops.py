# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0.

"""Extracted implementation cluster from legacy.py."""

from __future__ import annotations


class _LazyEngine:
    """Resolve basefwx attributes after legacy finishes loading."""

    def __getattr__(self, name: str):
        from .legacy import basefwx as _engine
        return getattr(_engine, name)


basefwx = _LazyEngine()

def _build_metadata(method: str, strip: bool, use_master: bool, *, aead: str='AESGCM', kdf: 'basefwx.typing.Optional[str]'=None, mode: 'basefwx.typing.Optional[str]'=None, obfuscation: 'basefwx.typing.Optional[basefwx.typing.Union[bool, str]]'=None, kdf_iters: 'basefwx.typing.Optional[int]'=None, argon2_time_cost: 'basefwx.typing.Optional[int]'=None, argon2_memory_cost: 'basefwx.typing.Optional[int]'=None, argon2_parallelism: 'basefwx.typing.Optional[int]'=None, pack: 'basefwx.typing.Optional[str]'=None) -> str:
    if strip:
        return ''
    timestamp = basefwx.datetime.now(basefwx.timezone.utc).isoformat().replace('+00:00', 'Z')
    version = getattr(basefwx, '__version__', basefwx.ENGINE_VERSION)
    kdf_label = (kdf or basefwx.USER_KDF or 'argon2id').lower()
    info = {'ENC-TIME': timestamp, 'ENC-VERSION': version, 'ENC-METHOD': method, 'ENC-MASTER': 'yes' if use_master else 'no', 'ENC-KEM': basefwx.MASTER_PQ_ALG if use_master else 'none', 'ENC-AEAD': aead, 'ENC-KDF': kdf_label}
    if mode:
        info['ENC-MODE'] = mode
    if obfuscation is not None:
        if isinstance(obfuscation, str):
            info['ENC-OBF'] = obfuscation.lower()
        else:
            info['ENC-OBF'] = 'yes' if obfuscation else 'no'
    if kdf_iters is not None:
        info['ENC-KDF-ITER'] = str(kdf_iters)
    if argon2_time_cost is not None:
        info['ENC-ARGON2-TC'] = str(argon2_time_cost)
    if argon2_memory_cost is not None:
        info['ENC-ARGON2-MEM'] = str(argon2_memory_cost)
    if argon2_parallelism is not None:
        info['ENC-ARGON2-PAR'] = str(argon2_parallelism)
    if pack:
        info[basefwx.PACK_META_KEY] = str(pack)
    data = basefwx.json.dumps(info, separators=(',', ':')).encode('utf-8')
    return basefwx.base64.b64encode(data).decode('utf-8')


def _decode_metadata(blob: str) -> 'basefwx.typing.Dict[str, basefwx.typing.Any]':
    if not blob:
        return {}
    try:
        raw = basefwx.base64.b64decode(blob.encode('utf-8'))
        return basefwx.json.loads(raw.decode('utf-8'))
    except Exception:
        return {}


def _split_metadata(payload: str) -> 'basefwx.typing.Tuple[str, str]':
    if basefwx.META_DELIM in payload:
        return payload.split(basefwx.META_DELIM, 1)
    return ('', payload)


def _split_with_delims(payload: str, delims: 'basefwx.typing.Iterable[str]', label: str) -> 'basefwx.typing.Tuple[str, str]':
    for delim in delims:
        if delim and delim in payload:
            return payload.split(delim, 1)
    raise ValueError(f'Malformed {label} payload')


def _apply_strip_attributes(path: 'basefwx.pathlib.Path') -> None:
    try:
        basefwx.os.utime(path, (0, 0))
    except Exception:
        pass


def _remove_input(path: 'basefwx.pathlib.Path', keep_input: bool, output_path: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None) -> None:
    if keep_input:
        return
    try:
        if output_path is not None:
            norm_in = basefwx._normalize_path(path)
            norm_out = basefwx._normalize_path(output_path)
            if norm_in == norm_out:
                return
    except Exception:
        pass
    try:
        if path.is_dir():
            basefwx.shutil.rmtree(path)
        else:
            basefwx.os.remove(path)
    except FileNotFoundError:
        pass


def _pack_mode_for_path(path: 'basefwx.pathlib.Path', compress: bool) -> str:
    if path.is_dir():
        return basefwx.PACK_TAR_XZ if compress else basefwx.PACK_TAR_GZ
    if compress:
        return basefwx.PACK_TAR_XZ
    return ''


def _pack_input_to_archive(path: 'basefwx.pathlib.Path', compress: bool, reporter: 'basefwx.typing.Optional[basefwx._ProgressReporter]'=None, file_index: int=0) -> 'basefwx.typing.Optional[tuple[basefwx.pathlib.Path, str, basefwx.tempfile.TemporaryDirectory]]':
    pack_flag = basefwx._pack_mode_for_path(path, compress)
    if not pack_flag:
        return None
    temp_dir = basefwx.tempfile.TemporaryDirectory(prefix='basefwx-pack-')
    base_name = path.stem if path.is_file() else path.name
    suffix = basefwx.PACK_SUFFIX_XZ if pack_flag == basefwx.PACK_TAR_XZ else basefwx.PACK_SUFFIX_GZ
    archive_path = basefwx.pathlib.Path(temp_dir.name) / f'{base_name}{suffix}'
    if reporter:
        reporter.update(file_index, 0.08, 'pack', path)
    mode = 'w:xz' if pack_flag == basefwx.PACK_TAR_XZ else 'w:gz'
    tar_kwargs: dict[str, basefwx.typing.Any] = {}
    if pack_flag == basefwx.PACK_TAR_XZ:
        tar_kwargs['preset'] = 9 | basefwx.lzma.PRESET_EXTREME
    else:
        tar_kwargs['compresslevel'] = 1
    with basefwx.tarfile.open(archive_path, mode, **tar_kwargs) as tar:
        tar.add(path, arcname=path.name)
    return (archive_path, pack_flag, temp_dir)


def _is_safe_tar_path(base_dir: 'basefwx.pathlib.Path', member_name: str) -> bool:
    if not member_name:
        return False
    member_path = basefwx.pathlib.PurePosixPath(member_name)
    if member_path.is_absolute():
        return False
    if '..' in member_path.parts:
        return False
    resolved_base = base_dir.resolve()
    resolved_target = (base_dir / member_path.as_posix()).resolve(strict=False)
    return resolved_base == resolved_target or resolved_base in resolved_target.parents


def _unpack_archive(archive_path: 'basefwx.pathlib.Path', pack_flag: str, reporter: 'basefwx.typing.Optional[basefwx._ProgressReporter]'=None, file_index: int=0, target_dir: 'basefwx.typing.Optional[basefwx.pathlib.Path]'=None) -> 'basefwx.pathlib.Path':
    mode = 'r:xz' if pack_flag == basefwx.PACK_TAR_XZ else 'r:gz'
    target_dir = target_dir or archive_path.parent
    roots: 'basefwx.typing.Set[str]' = set()
    if reporter:
        reporter.update(file_index, 0.9, 'unpack', archive_path)
    with basefwx.tarfile.open(archive_path, mode) as tar:
        members = tar.getmembers()
        for member in members:
            if not basefwx._is_safe_tar_path(target_dir, member.name):
                raise ValueError('Unsafe archive entry detected')
            parts = basefwx.pathlib.PurePosixPath(member.name).parts
            if parts:
                roots.add(parts[0])
        tar.extractall(target_dir, filter='data')
    try:
        archive_path.unlink()
    except FileNotFoundError:
        pass
    if len(roots) == 1:
        return target_dir / next(iter(roots))
    return target_dir


def _pack_flag_from_meta(meta: 'basefwx.typing.Dict[str, basefwx.typing.Any]', ext: str) -> str:
    flag = (meta.get(basefwx.PACK_META_KEY) or '').lower() if meta else ''
    if flag in (basefwx.PACK_TAR_GZ, basefwx.PACK_TAR_XZ):
        return flag
    ext_lower = (ext or '').lower()
    if ext_lower == basefwx.PACK_SUFFIX_GZ:
        return basefwx.PACK_TAR_GZ
    if ext_lower == basefwx.PACK_SUFFIX_XZ:
        return basefwx.PACK_TAR_XZ
    return ''


def _maybe_unpack_output(path: 'basefwx.pathlib.Path', pack_flag: str, reporter: 'basefwx.typing.Optional[basefwx._ProgressReporter]'=None, file_index: int=0, strip_metadata: bool=False) -> 'basefwx.pathlib.Path':
    if not pack_flag:
        return path
    extracted = basefwx._unpack_archive(path, pack_flag, reporter, file_index)
    if strip_metadata:
        try:
            basefwx._apply_strip_attributes(extracted)
        except Exception:
            pass
    return extracted


def _warn_on_metadata(meta: 'basefwx.typing.Dict[str, basefwx.typing.Any]', expected_method: str) -> None:
    if not meta:
        return
    recorded_method = meta.get('ENC-METHOD')
    recorded_version = meta.get('ENC-VERSION')
    hints = []
    if recorded_method and recorded_method != expected_method:
        hints.append(recorded_method)
    if recorded_version and recorded_version != basefwx.ENGINE_VERSION:
        hints.append(recorded_version)
    if hints:
        print('Did you mean to use:\n' + ' or '.join(hints))


def _normalize_path(path_like: 'basefwx.typing.Union[str, basefwx.pathlib.Path]') -> 'basefwx.pathlib.Path':
    if isinstance(path_like, basefwx.pathlib.Path):
        path = path_like
    else:
        path = basefwx.pathlib.Path(str(path_like))
    path = path.expanduser()
    try:
        return path.resolve(strict=False)
    except Exception:
        return path


def _ensure_existing_file(path: 'basefwx.pathlib.Path') -> None:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f'Input file not found: {path}')


def _ensure_size_limit(path: 'basefwx.pathlib.Path', max_bytes: int=None) -> None:
    limit = max_bytes or basefwx.MAX_INPUT_BYTES
    size = path.stat().st_size
    if size > limit:
        human_size = basefwx._human_readable_size(size)
        human_limit = basefwx._human_readable_size(limit)
        raise ValueError(f'{path.name} is {human_size}, exceeding the {human_limit} limit for this mode')


def _resolve_password(password: 'basefwx.typing.Union[str, bytes, bytearray, memoryview]', use_master: bool=True) -> 'basefwx.typing.Union[str, bytes]':
    if password is None:
        if not use_master:
            raise ValueError('Password required when master key usage is disabled')
        return ''
    if isinstance(password, (bytes, bytearray, memoryview)):
        return bytes(password)
    if isinstance(password, basefwx.pathlib.Path):
        candidate = password.expanduser()
        if candidate.is_file():
            return candidate.read_bytes()
        return str(candidate)
    if password == '':
        if not use_master:
            raise ValueError('Password required when master key usage is disabled')
        return ''
    if isinstance(password, str) and password.startswith('yubikey:'):
        label = password.split(':', 1)[1] or 'default'
        try:
            from .yubikey_pq import YubiKeyPQKeyStore, YubiKeyUnavailableError
        except ImportError as exc:
            raise ValueError("YubiKey support is optional. Install python-fido2 inside your environment to use 'yubikey:<label>' password specifications.") from exc
        try:
            vault = YubiKeyPQKeyStore()
            return vault.derive_passphrase(label.strip() or 'default')
        except YubiKeyUnavailableError as exc:
            raise ValueError(str(exc)) from exc
    candidate = basefwx.pathlib.Path(password).expanduser()
    if candidate.is_file():
        return candidate.read_bytes()
    return password


def _coerce_file_list(files) -> 'basefwx.typing.List[basefwx.pathlib.Path]':
    if isinstance(files, (str, basefwx.pathlib.Path)):
        candidates = [files]
    else:
        candidates = list(files)
    if not candidates:
        raise ValueError('No files provided')
    normalized = []
    for item in candidates:
        normalized.append(basefwx._normalize_path(item))
    return normalized


def _is_seekable(handle) -> bool:
    try:
        return bool(handle.seekable())
    except Exception:
        return False


def _is_pathlike_target(obj) -> bool:
    return isinstance(obj, (str, bytes, basefwx.os.PathLike, basefwx.pathlib.Path))


def _wrap_pack_header(blob: bytes, pack_flag: str) -> bytes:
    if pack_flag not in (basefwx.PACK_TAR_GZ, basefwx.PACK_TAR_XZ):
        raise ValueError('Unsupported pack flag')
    header = basefwx.FWX_PACK_MAGIC + bytes([ord(pack_flag)]) + len(blob).to_bytes(8, 'big')
    return header + blob


def _unwrap_pack_header(data: bytes) -> 'basefwx.typing.Optional[tuple[str, bytes]]':
    if len(data) < basefwx.FWX_PACK_HEADER_LEN:
        return None
    if not data.startswith(basefwx.FWX_PACK_MAGIC):
        return None
    flag = chr(data[len(basefwx.FWX_PACK_MAGIC)])
    if flag not in (basefwx.PACK_TAR_GZ, basefwx.PACK_TAR_XZ):
        return None
    length_start = len(basefwx.FWX_PACK_MAGIC) + 1
    length = int.from_bytes(data[length_start:length_start + 8], 'big')
    if length != len(data) - basefwx.FWX_PACK_HEADER_LEN:
        return None
    return (flag, data[basefwx.FWX_PACK_HEADER_LEN:])
