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

    private static byte[] concat(byte[] a, byte[] b) {
        if (a.length == 0) {
            return Arrays.copyOf(b, b.length);
        }
        if (b.length == 0) {
            return Arrays.copyOf(a, a.length);
        }
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
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
            if (!started) {
                throw new IllegalArgumentException("LiveEncryptor.start() must be called before update()");
            }
            if (finalized) {
                throw new IllegalArgumentException("LiveEncryptor already finalized");
            }
            byte[] payload = chunk == null ? new byte[0] : chunk;
            if (payload.length == 0) {
                return new byte[0];
            }
            byte[] nonce = nonceForSequence(noncePrefix, sequence);
            byte[] aad = liveAad(Constants.LIVE_FRAME_TYPE_DATA, sequence, payload.length);
            byte[] ct = Crypto.aesGcmEncryptWithIv(key, nonce, payload, aad);
            byte[] body = new byte[4 + ct.length];
            writeU32(body, 0, payload.length);
            System.arraycopy(ct, 0, body, 4, ct.length);
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

        public LiveDecryptor(String password, boolean useMaster) {
            this.password = BaseFwx.resolvePasswordBytes(password, useMaster);
            this.useMaster = useMaster;
            this.started = false;
            this.finished = false;
            this.expectedSequence = 0L;
            this.key = new byte[0];
            this.noncePrefix = new byte[0];
            this.buffer = new byte[0];
        }

        public LiveDecryptor(String password) {
            this(password, true);
        }

        private void parseHeader(byte[] body) {
            if (body.length < HEADER_FIXED_LEN) {
                throw new IllegalArgumentException("Truncated live stream header");
            }
            int keyMode = body[0] & 0xFF;
            int saltLen = body[1] & 0xFF;
            int nonceLen = body[2] & 0xFF;
            int keyHeaderLen = readU32(body, 4);
            int iters = readU32(body, 8);

            int need = HEADER_FIXED_LEN + keyHeaderLen + saltLen + nonceLen;
            if (body.length != need) {
                throw new IllegalArgumentException("Invalid live stream header length");
            }

            int offset = HEADER_FIXED_LEN;
            byte[] keyHeader = Arrays.copyOfRange(body, offset, offset + keyHeaderLen);
            offset += keyHeaderLen;
            byte[] salt = Arrays.copyOfRange(body, offset, offset + saltLen);
            offset += saltLen;
            byte[] prefix = Arrays.copyOfRange(body, offset, offset + nonceLen);
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

        private byte[] decryptDataFrame(long sequence, byte[] body) {
            if (body.length < 4 + Constants.AEAD_TAG_LEN) {
                throw new IllegalArgumentException("Truncated live data frame");
            }
            int plainLen = readU32(body, 0);
            byte[] ct = Arrays.copyOfRange(body, 4, body.length);
            byte[] nonce = nonceForSequence(noncePrefix, sequence);
            byte[] aad = liveAad(Constants.LIVE_FRAME_TYPE_DATA, sequence, plainLen);
            byte[] plain;
            try {
                plain = Crypto.aesGcmDecryptWithIv(key, nonce, ct, aad);
            } catch (RuntimeException exc) {
                throw new IllegalArgumentException("Live frame authentication failed", exc);
            }
            if (plain.length != plainLen) {
                throw new IllegalArgumentException("Live frame length mismatch");
            }
            return plain;
        }

        private void decryptFinFrame(long sequence, byte[] body) {
            if (body.length < Constants.AEAD_TAG_LEN) {
                throw new IllegalArgumentException("Truncated live FIN frame");
            }
            byte[] nonce = nonceForSequence(noncePrefix, sequence);
            byte[] aad = liveAad(Constants.LIVE_FRAME_TYPE_FIN, sequence, 0);
            byte[] plain;
            try {
                plain = Crypto.aesGcmDecryptWithIv(key, nonce, body, aad);
            } catch (RuntimeException exc) {
                throw new IllegalArgumentException("Live FIN authentication failed", exc);
            }
            if (plain.length != 0) {
                throw new IllegalArgumentException("Live FIN frame carries unexpected payload");
            }
            finished = true;
        }

        public List<byte[]> update(byte[] data) {
            if (finished && data != null && data.length > 0) {
                throw new IllegalArgumentException("Live stream already finalized");
            }
            if (data != null && data.length > 0) {
                buffer = concat(buffer, data);
            }
            List<byte[]> outputs = new ArrayList<byte[]>();
            while (buffer.length >= FRAME_HEADER_LEN) {
                if (!Arrays.equals(Arrays.copyOfRange(buffer, 0, LIVE_MAGIC.length), LIVE_MAGIC)) {
                    throw new IllegalArgumentException("Invalid live frame magic");
                }
                int version = buffer[4] & 0xFF;
                if (version != Constants.LIVE_FRAME_VERSION) {
                    throw new IllegalArgumentException("Unsupported live frame version");
                }
                int frameType = buffer[5] & 0xFF;
                long sequence = readU64(buffer, 6);
                int bodyLen = readU32(buffer, 14);
                if (bodyLen < 0 || bodyLen > Constants.LIVE_MAX_BODY) {
                    throw new IllegalArgumentException("Live frame too large");
                }
                long frameLenLong = (long) FRAME_HEADER_LEN + (long) bodyLen;
                if (frameLenLong > Integer.MAX_VALUE) {
                    throw new IllegalArgumentException("Live frame too large");
                }
                int frameLen = (int) frameLenLong;
                if (buffer.length < frameLen) {
                    break;
                }
                byte[] body = Arrays.copyOfRange(buffer, FRAME_HEADER_LEN, frameLen);
                buffer = Arrays.copyOfRange(buffer, frameLen, buffer.length);

                if (!started) {
                    if (frameType != Constants.LIVE_FRAME_TYPE_HEADER || sequence != 0L) {
                        throw new IllegalArgumentException("Live stream must start with header frame");
                    }
                    parseHeader(body);
                    continue;
                }
                if (sequence != expectedSequence) {
                    throw new IllegalArgumentException("Live frame sequence mismatch");
                }
                if (frameType == Constants.LIVE_FRAME_TYPE_DATA) {
                    byte[] plain = decryptDataFrame(sequence, body);
                    if (plain.length > 0) {
                        outputs.add(plain);
                    }
                } else if (frameType == Constants.LIVE_FRAME_TYPE_FIN) {
                    decryptFinFrame(sequence, body);
                } else {
                    throw new IllegalArgumentException("Unexpected live frame type");
                }
                expectedSequence += 1L;
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
            if (buffer.length > 0) {
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
                byte[] payload = read == buf.length ? Arrays.copyOf(buf, buf.length) : Arrays.copyOf(buf, read);
                byte[] frame = encryptor.update(payload);
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
                byte[] frame = read == buf.length ? Arrays.copyOf(buf, buf.length) : Arrays.copyOf(buf, read);
                List<byte[]> plains = decryptor.update(frame);
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
