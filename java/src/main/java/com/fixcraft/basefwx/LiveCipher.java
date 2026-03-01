package com.fixcraft.basefwx;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class LiveCipher {
    private LiveCipher() {}

    private static final byte[] LIVE_MAGIC = Constants.LIVE_FRAME_MAGIC;
    private static final int FRAME_HEADER_LEN = Constants.LIVE_FRAME_HEADER_LEN;
    private static final int HEADER_FIXED_LEN = Constants.LIVE_HEADER_FIXED_LEN;

    private static boolean bytesEqualAt(byte[] data, int offset, byte[] expected) {
        if (offset < 0 || expected == null || offset + expected.length > data.length) {
            return false;
        }
        for (int i = 0; i < expected.length; i++) {
            if (data[offset + i] != expected[i]) {
                return false;
            }
        }
        return true;
    }

    private static void checkSliceBounds(byte[] data, int off, int len, String name) {
        if (data == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        if (off < 0 || len < 0 || off > data.length - len) {
            throw new IllegalArgumentException("Invalid " + name + " slice");
        }
    }

    private static void compactInPlace(byte[] buffer, int srcOffset, int length) {
        if (length > 0 && srcOffset > 0) {
            System.arraycopy(buffer, srcOffset, buffer, 0, length);
        }
    }

    private static byte[] growBuffer(byte[] current, int required) {
        int cap = current.length == 0 ? 4096 : current.length;
        while (cap < required) {
            int doubled = cap << 1;
            if (doubled <= cap) {
                cap = required;
                break;
            }
            cap = doubled;
        }
        return Arrays.copyOf(current, cap);
    }

    private static int hardenFwxAesIterations(byte[] password, int iterations) {
        if (password == null || password.length == 0) {
            return iterations;
        }
        if (Constants.TEST_KDF_OVERRIDE) {
            return iterations;
        }
        if (password.length < Constants.SHORT_PASSWORD_MIN) {
            return Math.max(iterations, Constants.SHORT_PBKDF2_ITERS);
        }
        return iterations;
    }

    private static byte[] nonceForSequence(byte[] prefix, long sequence) {
        if (prefix == null || prefix.length != Constants.LIVE_NONCE_PREFIX_LEN) {
            throw new IllegalArgumentException("Invalid live nonce prefix");
        }
        if (sequence < 0) {
            throw new IllegalArgumentException("Live stream sequence overflow");
        }
        byte[] nonce = new byte[Constants.AEAD_NONCE_LEN];
        System.arraycopy(prefix, 0, nonce, 0, prefix.length);
        writeU64(nonce, prefix.length, sequence);
        return nonce;
    }

    private static byte[] liveAad(int frameType, long sequence, int plainLen) {
        if (plainLen < 0) {
            throw new IllegalArgumentException("Invalid live frame length");
        }
        byte[] aad = new byte[FRAME_HEADER_LEN];
        System.arraycopy(LIVE_MAGIC, 0, aad, 0, LIVE_MAGIC.length);
        aad[4] = (byte) (Constants.LIVE_FRAME_VERSION & 0xFF);
        aad[5] = (byte) (frameType & 0xFF);
        writeU64(aad, 6, sequence);
        writeU32(aad, 14, plainLen);
        return aad;
    }

    private static byte[] packFrame(int frameType, long sequence, byte[] body) {
        if (body.length > Constants.LIVE_MAX_BODY) {
            throw new IllegalArgumentException("Live frame body too large");
        }
        byte[] frame = new byte[FRAME_HEADER_LEN + body.length];
        System.arraycopy(LIVE_MAGIC, 0, frame, 0, LIVE_MAGIC.length);
        frame[4] = (byte) (Constants.LIVE_FRAME_VERSION & 0xFF);
        frame[5] = (byte) (frameType & 0xFF);
        writeU64(frame, 6, sequence);
        writeU32(frame, 14, body.length);
        System.arraycopy(body, 0, frame, FRAME_HEADER_LEN, body.length);
        return frame;
    }

    private static byte[] buildSessionHeader(int keyMode,
                                             byte[] keyHeader,
                                             byte[] salt,
                                             byte[] noncePrefix,
                                             int iterations) {
        int total = HEADER_FIXED_LEN + keyHeader.length + salt.length + noncePrefix.length;
        byte[] out = new byte[total];
        out[0] = (byte) (keyMode & 0xFF);
        out[1] = (byte) (salt.length & 0xFF);
        out[2] = (byte) (noncePrefix.length & 0xFF);
        out[3] = 0;
        writeU32(out, 4, keyHeader.length);
        writeU32(out, 8, iterations);
        int offset = HEADER_FIXED_LEN;
        System.arraycopy(keyHeader, 0, out, offset, keyHeader.length);
        offset += keyHeader.length;
        System.arraycopy(salt, 0, out, offset, salt.length);
        offset += salt.length;
        System.arraycopy(noncePrefix, 0, out, offset, noncePrefix.length);
        return out;
    }

    private static void writeU32(byte[] out, int offset, int value) {
        out[offset] = (byte) ((value >>> 24) & 0xFF);
        out[offset + 1] = (byte) ((value >>> 16) & 0xFF);
        out[offset + 2] = (byte) ((value >>> 8) & 0xFF);
        out[offset + 3] = (byte) (value & 0xFF);
    }

    private static int readU32(byte[] in, int offset) {
        return ((in[offset] & 0xFF) << 24)
            | ((in[offset + 1] & 0xFF) << 16)
            | ((in[offset + 2] & 0xFF) << 8)
            | (in[offset + 3] & 0xFF);
    }

    private static void writeU64(byte[] out, int offset, long value) {
        out[offset] = (byte) ((value >>> 56) & 0xFF);
        out[offset + 1] = (byte) ((value >>> 48) & 0xFF);
        out[offset + 2] = (byte) ((value >>> 40) & 0xFF);
        out[offset + 3] = (byte) ((value >>> 32) & 0xFF);
        out[offset + 4] = (byte) ((value >>> 24) & 0xFF);
        out[offset + 5] = (byte) ((value >>> 16) & 0xFF);
        out[offset + 6] = (byte) ((value >>> 8) & 0xFF);
        out[offset + 7] = (byte) (value & 0xFF);
    }

    private static long readU64(byte[] in, int offset) {
        return ((long) (in[offset] & 0xFF) << 56)
            | ((long) (in[offset + 1] & 0xFF) << 48)
            | ((long) (in[offset + 2] & 0xFF) << 40)
            | ((long) (in[offset + 3] & 0xFF) << 32)
            | ((long) (in[offset + 4] & 0xFF) << 24)
            | ((long) (in[offset + 5] & 0xFF) << 16)
            | ((long) (in[offset + 6] & 0xFF) << 8)
            | ((long) (in[offset + 7] & 0xFF));
    }

    public static final class LiveEncryptor {
        private final byte[] password;
        private final boolean useMaster;

        private boolean started;
        private boolean finalized;
        private long sequence;
        private byte[] key;
        private byte[] noncePrefix;

        public LiveEncryptor(String password, boolean useMaster) {
            this.password = BaseFwx.resolvePasswordBytes(password, useMaster);
            this.useMaster = useMaster;
            this.started = false;
            this.finalized = false;
            this.sequence = 1L;
            this.key = new byte[0];
            this.noncePrefix = new byte[0];
        }

        public LiveEncryptor(String password) {
            this(password, true);
        }

        private byte[] initSession() {
            boolean hasPassword = password.length > 0;
            int keyMode = Constants.LIVE_KEYMODE_PBKDF2;
            byte[] keyHeader = new byte[0];
            byte[] salt = new byte[0];
            int iters = 0;
            byte[] sessionKey;

            if (useMaster) {
                try {
                    KeyWrap.MaskKeyResult mask = KeyWrap.prepareMaskKey(
                        password,
                        true,
                        Constants.FWXAES_MASK_INFO,
                        false,
                        Constants.FWXAES_AAD,
                        new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
                    );
                    boolean useWrap = mask.usedMaster || !hasPassword;
                    if (useWrap) {
                        keyMode = Constants.LIVE_KEYMODE_WRAP;
                        keyHeader = Format.packLengthPrefixed(Arrays.asList(mask.userBlob, mask.masterBlob));
                        sessionKey = Crypto.hkdfSha256(mask.maskKey, Constants.FWXAES_KEY_INFO, Constants.FWXAES_KEY_LEN);
                        noncePrefix = Crypto.randomBytes(Constants.LIVE_NONCE_PREFIX_LEN);
                        key = sessionKey;
                        return packFrame(Constants.LIVE_FRAME_TYPE_HEADER, 0L,
                            buildSessionHeader(keyMode, keyHeader, salt, noncePrefix, 0));
                    }
                } catch (RuntimeException exc) {
                    if (!hasPassword) {
                        throw exc;
                    }
                }
            }

            if (!hasPassword) {
                throw new IllegalArgumentException("Password required when live stream master key wrapping is disabled");
            }
            salt = Crypto.randomBytes(Constants.FWXAES_SALT_LEN);
            iters = hardenFwxAesIterations(password, Constants.FWXAES_PBKDF2_ITERS);
            sessionKey = Crypto.pbkdf2HmacSha256(password, salt, iters, Constants.FWXAES_KEY_LEN);
            noncePrefix = Crypto.randomBytes(Constants.LIVE_NONCE_PREFIX_LEN);
            key = sessionKey;
            return packFrame(Constants.LIVE_FRAME_TYPE_HEADER, 0L,
                buildSessionHeader(keyMode, keyHeader, salt, noncePrefix, iters));
        }

        public byte[] start() {
            if (started) {
                throw new IllegalArgumentException("LiveEncryptor already started");
            }
            if (finalized) {
                throw new IllegalArgumentException("LiveEncryptor already finalized");
            }
            byte[] frame = initSession();
            started = true;
            return frame;
        }

        public byte[] update(byte[] chunk) {
            if (chunk == null) {
                return update(new byte[0], 0, 0);
            }
            return update(chunk, 0, chunk.length);
        }

        public byte[] update(byte[] chunk, int off, int len) {
            if (!started) {
                throw new IllegalArgumentException("LiveEncryptor.start() must be called before update()");
            }
            if (finalized) {
                throw new IllegalArgumentException("LiveEncryptor already finalized");
            }
            checkSliceBounds(chunk, off, len, "chunk");
            if (len == 0) {
                return new byte[0];
            }
            byte[] nonce = nonceForSequence(noncePrefix, sequence);
            byte[] aad = liveAad(Constants.LIVE_FRAME_TYPE_DATA, sequence, len);
            int ctLen = len + Constants.AEAD_TAG_LEN;
            byte[] body = new byte[4 + ctLen];
            writeU32(body, 0, len);
            int written = Crypto.aesGcmEncryptWithIvInto(
                key,
                nonce,
                chunk,
                off,
                len,
                body,
                4,
                aad
            );
            if (written != ctLen) {
                body = Arrays.copyOf(body, Math.max(4, 4 + written));
            }
            byte[] frame = packFrame(Constants.LIVE_FRAME_TYPE_DATA, sequence, body);
            sequence += 1L;
            return frame;
        }

        public byte[] finish() {
            if (!started) {
                throw new IllegalArgumentException("LiveEncryptor.start() must be called before finish()");
            }
            if (finalized) {
                throw new IllegalArgumentException("LiveEncryptor already finalized");
            }
            byte[] nonce = nonceForSequence(noncePrefix, sequence);
            byte[] aad = liveAad(Constants.LIVE_FRAME_TYPE_FIN, sequence, 0);
            byte[] finBlob = Crypto.aesGcmEncryptWithIv(key, nonce, new byte[0], aad);
            byte[] frame = packFrame(Constants.LIVE_FRAME_TYPE_FIN, sequence, finBlob);
            sequence += 1L;
            finalized = true;
            return frame;
        }
    }

    public static final class LiveDecryptor {
        private final byte[] password;
        private final boolean useMaster;

        private boolean started;
        private boolean finished;
        private long expectedSequence;
        private byte[] key;
        private byte[] noncePrefix;
        private byte[] buffer;
        private int bufferStart;
        private int bufferEnd;

        public LiveDecryptor(String password, boolean useMaster) {
            this.password = BaseFwx.resolvePasswordBytes(password, useMaster);
            this.useMaster = useMaster;
            this.started = false;
            this.finished = false;
            this.expectedSequence = 0L;
            this.key = new byte[0];
            this.noncePrefix = new byte[0];
            this.buffer = new byte[0];
            this.bufferStart = 0;
            this.bufferEnd = 0;
        }

        public LiveDecryptor(String password) {
            this(password, true);
        }

        private int bufferedSize() {
            return bufferEnd - bufferStart;
        }

        private void ensureAppendCapacity(int incoming) {
            int unread = bufferedSize();
            if (incoming <= 0) {
                return;
            }
            if (buffer.length == 0) {
                buffer = new byte[Math.max(4096, incoming)];
                bufferStart = 0;
                bufferEnd = 0;
                return;
            }
            if (buffer.length - bufferEnd >= incoming) {
                return;
            }
            if (bufferStart > 0 && buffer.length - unread >= incoming) {
                compactInPlace(buffer, bufferStart, unread);
                bufferStart = 0;
                bufferEnd = unread;
                if (buffer.length - bufferEnd >= incoming) {
                    return;
                }
            }
            buffer = growBuffer(buffer, unread + incoming);
            if (bufferStart > 0 && unread > 0) {
                compactInPlace(buffer, bufferStart, unread);
            }
            bufferStart = 0;
            bufferEnd = unread;
        }

        private void append(byte[] data, int off, int len) {
            if (len <= 0) {
                return;
            }
            ensureAppendCapacity(len);
            System.arraycopy(data, off, buffer, bufferEnd, len);
            bufferEnd += len;
        }

        private void maybeCompactBuffer() {
            if (bufferStart == 0) {
                return;
            }
            if (bufferStart < (1 << 20) && bufferStart * 2 < bufferEnd) {
                return;
            }
            int unread = bufferedSize();
            compactInPlace(buffer, bufferStart, unread);
            bufferStart = 0;
            bufferEnd = unread;
        }

        private void parseHeader(byte[] data, int bodyOff, int bodyLen) {
            if (bodyLen < HEADER_FIXED_LEN) {
                throw new IllegalArgumentException("Truncated live stream header");
            }
            int keyMode = data[bodyOff] & 0xFF;
            int saltLen = data[bodyOff + 1] & 0xFF;
            int nonceLen = data[bodyOff + 2] & 0xFF;
            int keyHeaderLen = readU32(data, bodyOff + 4);
            int iters = readU32(data, bodyOff + 8);
            if (keyHeaderLen < 0) {
                throw new IllegalArgumentException("Invalid live stream key header length");
            }

            long need = (long) HEADER_FIXED_LEN + (long) keyHeaderLen + (long) saltLen + (long) nonceLen;
            if (bodyLen != need) {
                throw new IllegalArgumentException("Invalid live stream header length");
            }

            int offset = bodyOff + HEADER_FIXED_LEN;
            byte[] keyHeader = keyHeaderLen == 0
                ? new byte[0]
                : Arrays.copyOfRange(data, offset, offset + keyHeaderLen);
            offset += keyHeaderLen;
            byte[] salt = saltLen == 0
                ? new byte[0]
                : Arrays.copyOfRange(data, offset, offset + saltLen);
            offset += saltLen;
            byte[] prefix = nonceLen == 0
                ? new byte[0]
                : Arrays.copyOfRange(data, offset, offset + nonceLen);
            if (prefix.length != Constants.LIVE_NONCE_PREFIX_LEN) {
                throw new IllegalArgumentException("Invalid live stream nonce prefix");
            }

            if (keyMode == Constants.LIVE_KEYMODE_WRAP) {
                if (keyHeader.length == 0) {
                    throw new IllegalArgumentException("Missing live key header");
                }
                List<byte[]> parts = Format.unpackLengthPrefixed(keyHeader, 2);
                byte[] maskKey = KeyWrap.recoverMaskKey(
                    parts.get(0),
                    parts.get(1),
                    password,
                    useMaster,
                    Constants.FWXAES_MASK_INFO,
                    Constants.FWXAES_AAD,
                    new KeyWrap.KdfOptions("pbkdf2", Constants.USER_KDF_ITERATIONS)
                );
                key = Crypto.hkdfSha256(maskKey, Constants.FWXAES_KEY_INFO, Constants.FWXAES_KEY_LEN);
            } else if (keyMode == Constants.LIVE_KEYMODE_PBKDF2) {
                if (password.length == 0) {
                    throw new IllegalArgumentException("Password required for PBKDF2 live stream");
                }
                if (salt.length == 0) {
                    throw new IllegalArgumentException("Missing live stream PBKDF2 salt");
                }
                if (iters <= 0) {
                    throw new IllegalArgumentException("Invalid live stream PBKDF2 iterations");
                }
                key = Crypto.pbkdf2HmacSha256(password, salt, iters, Constants.FWXAES_KEY_LEN);
            } else {
                throw new IllegalArgumentException("Unsupported live key mode");
            }

            noncePrefix = prefix;
            started = true;
            expectedSequence = 1L;
        }

        private byte[] decryptDataFrame(long sequence, byte[] data, int off, int len) {
            if (len < 4 + Constants.AEAD_TAG_LEN) {
                throw new IllegalArgumentException("Truncated live data frame");
            }
            int plainLen = readU32(data, off);
            if (plainLen < 0) {
                throw new IllegalArgumentException("Invalid live frame length");
            }
            int ctOff = off + 4;
            int ctLen = len - 4;
            byte[] nonce = nonceForSequence(noncePrefix, sequence);
            byte[] aad = liveAad(Constants.LIVE_FRAME_TYPE_DATA, sequence, plainLen);
            byte[] plain = new byte[plainLen];
            int written;
            try {
                written = Crypto.aesGcmDecryptWithIvInto(key, nonce, data, ctOff, ctLen, plain, 0, aad);
            } catch (RuntimeException exc) {
                throw new IllegalArgumentException("Live frame authentication failed", exc);
            }
            if (written != plainLen) {
                throw new IllegalArgumentException("Live frame length mismatch");
            }
            return plain;
        }

        private void decryptFinFrame(long sequence, byte[] data, int off, int len) {
            if (len < Constants.AEAD_TAG_LEN) {
                throw new IllegalArgumentException("Truncated live FIN frame");
            }
            byte[] nonce = nonceForSequence(noncePrefix, sequence);
            byte[] aad = liveAad(Constants.LIVE_FRAME_TYPE_FIN, sequence, 0);
            byte[] plain = new byte[Math.max(0, len - Constants.AEAD_TAG_LEN)];
            int written;
            try {
                written = Crypto.aesGcmDecryptWithIvInto(key, nonce, data, off, len, plain, 0, aad);
            } catch (RuntimeException exc) {
                throw new IllegalArgumentException("Live FIN authentication failed", exc);
            }
            if (written != 0) {
                throw new IllegalArgumentException("Live FIN frame carries unexpected payload");
            }
            finished = true;
        }

        public List<byte[]> update(byte[] data) {
            if (data == null) {
                return update(new byte[0], 0, 0);
            }
            return update(data, 0, data.length);
        }

        public List<byte[]> update(byte[] data, int off, int len) {
            if (finished && len > 0) {
                throw new IllegalArgumentException("Live stream already finalized");
            }
            checkSliceBounds(data, off, len, "frame");
            if (len > 0) {
                append(data, off, len);
            }
            List<byte[]> outputs = new ArrayList<byte[]>();
            while (bufferedSize() >= FRAME_HEADER_LEN) {
                int frameStart = bufferStart;
                if (!bytesEqualAt(buffer, frameStart, LIVE_MAGIC)) {
                    throw new IllegalArgumentException("Invalid live frame magic");
                }
                int version = buffer[frameStart + 4] & 0xFF;
                if (version != Constants.LIVE_FRAME_VERSION) {
                    throw new IllegalArgumentException("Unsupported live frame version");
                }
                int frameType = buffer[frameStart + 5] & 0xFF;
                long sequence = readU64(buffer, frameStart + 6);
                int bodyLen = readU32(buffer, frameStart + 14);
                if (bodyLen < 0 || bodyLen > Constants.LIVE_MAX_BODY) {
                    throw new IllegalArgumentException("Live frame too large");
                }
                long frameLenLong = (long) FRAME_HEADER_LEN + (long) bodyLen;
                if (frameLenLong > Integer.MAX_VALUE) {
                    throw new IllegalArgumentException("Live frame too large");
                }
                int frameLen = (int) frameLenLong;
                if (bufferedSize() < frameLen) {
                    break;
                }
                int bodyOff = frameStart + FRAME_HEADER_LEN;

                if (!started) {
                    if (frameType != Constants.LIVE_FRAME_TYPE_HEADER || sequence != 0L) {
                        throw new IllegalArgumentException("Live stream must start with header frame");
                    }
                    parseHeader(buffer, bodyOff, bodyLen);
                } else {
                    if (sequence != expectedSequence) {
                        throw new IllegalArgumentException("Live frame sequence mismatch");
                    }
                    if (frameType == Constants.LIVE_FRAME_TYPE_DATA) {
                        byte[] plain = decryptDataFrame(sequence, buffer, bodyOff, bodyLen);
                        if (plain.length > 0) {
                            outputs.add(plain);
                        }
                    } else if (frameType == Constants.LIVE_FRAME_TYPE_FIN) {
                        decryptFinFrame(sequence, buffer, bodyOff, bodyLen);
                    } else {
                        throw new IllegalArgumentException("Unexpected live frame type");
                    }
                    expectedSequence += 1L;
                }
                bufferStart += frameLen;
                if (bufferStart == bufferEnd) {
                    bufferStart = 0;
                    bufferEnd = 0;
                    break;
                }
                maybeCompactBuffer();
            }
            return outputs;
        }

        public void finish() {
            if (!started) {
                throw new IllegalArgumentException("Missing live stream header frame");
            }
            if (!finished) {
                throw new IllegalArgumentException("Live stream ended without FIN frame");
            }
            if (bufferedSize() > 0) {
                throw new IllegalArgumentException("Trailing bytes after live stream FIN");
            }
        }
    }

    public static List<byte[]> fwxAesLiveEncryptChunks(Iterable<byte[]> chunks,
                                                       String password,
                                                       boolean useMaster) {
        LiveEncryptor encryptor = new LiveEncryptor(password, useMaster);
        List<byte[]> out = new ArrayList<byte[]>();
        out.add(encryptor.start());
        for (byte[] chunk : chunks) {
            byte[] frame = encryptor.update(chunk == null ? new byte[0] : chunk);
            if (frame.length > 0) {
                out.add(frame);
            }
        }
        out.add(encryptor.finish());
        return out;
    }

    public static List<byte[]> fwxAesLiveDecryptChunks(Iterable<byte[]> chunks,
                                                       String password,
                                                       boolean useMaster) {
        LiveDecryptor decryptor = new LiveDecryptor(password, useMaster);
        List<byte[]> out = new ArrayList<byte[]>();
        for (byte[] chunk : chunks) {
            out.addAll(decryptor.update(chunk == null ? new byte[0] : chunk));
        }
        decryptor.finish();
        return out;
    }

    public static long fwxAesLiveEncryptStream(InputStream source,
                                               OutputStream dest,
                                               String password,
                                               boolean useMaster,
                                               int chunkSize) {
        if (source == null || dest == null) {
            throw new IllegalArgumentException("Source and destination streams are required");
        }
        int chunk = chunkSize > 0 ? chunkSize : Constants.STREAM_CHUNK_SIZE;
        LiveEncryptor encryptor = new LiveEncryptor(password, useMaster);
        long total = 0L;
        try {
            byte[] header = encryptor.start();
            dest.write(header);
            total += header.length;

            byte[] buf = new byte[chunk];
            int read;
            while ((read = source.read(buf)) != -1) {
                byte[] frame = encryptor.update(buf, 0, read);
                if (frame.length > 0) {
                    dest.write(frame);
                    total += frame.length;
                }
            }
            byte[] fin = encryptor.finish();
            dest.write(fin);
            total += fin.length;
            dest.flush();
        } catch (IOException exc) {
            throw new IllegalStateException("Live stream encrypt failed", exc);
        }
        return total;
    }

    public static long fwxAesLiveDecryptStream(InputStream source,
                                               OutputStream dest,
                                               String password,
                                               boolean useMaster,
                                               int chunkSize) {
        if (source == null || dest == null) {
            throw new IllegalArgumentException("Source and destination streams are required");
        }
        int chunk = chunkSize > 0 ? chunkSize : Constants.STREAM_CHUNK_SIZE;
        LiveDecryptor decryptor = new LiveDecryptor(password, useMaster);
        long written = 0L;
        try {
            byte[] buf = new byte[chunk];
            int read;
            while ((read = source.read(buf)) != -1) {
                List<byte[]> plains = decryptor.update(buf, 0, read);
                for (byte[] plain : plains) {
                    if (plain.length > 0) {
                        dest.write(plain);
                        written += plain.length;
                    }
                }
            }
            decryptor.finish();
            dest.flush();
        } catch (IOException exc) {
            throw new IllegalStateException("Live stream decrypt failed", exc);
        }
        return written;
    }
}
