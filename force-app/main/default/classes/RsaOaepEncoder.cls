/**
 * @description EME-OAEP encoding/decoding for RSAES-OAEP encryption scheme
 * @see {@link https://tools.ietf.org/html/rfc8017#section-7.1}
 */
public class RsaOaepEncoder implements RsaPaddingScheme {
    private final static Map<String, Integer> HASH_OCTET_LENGTHS = new Map<String, Integer> {
        'SHA1'    => 20, // 160 bits
        'SHA-256' => 32, // 256 bits
        'SHA-512' => 64  // 512 bits
    };

    private final static Blob EMPTY_BLOB = EncodingUtil.convertFromHex('');
    private final static ByteBlob X00 = ByteBlob.fromByteArray(new Integer[] { 0 });
    private final static ByteBlob X01 = ByteBlob.fromByteArray(new Integer[] { 1 });

    private final String hashAlgorithm;
    private final Integer hLen;

    /**
     * @description Initializes a new instance of the RsaOaepEncoder class.
     * @param hashAlgorithm The hash algorithm to be used during encoding/decoding. Can be 'SHA1', 'SHA-256' or 'SHA-512'.
     */
    public RsaOaepEncoder(String hashAlgorithm) {
        if (hashAlgorithm == null) {
            throw buildInvalidParamException('hashAlgorithm', 'Hash algorithm cannot be null');
        }

        if (!HASH_OCTET_LENGTHS.containsKey(hashAlgorithm)) {
            throw buildInvalidParamException('hashAlgorithm', 'Unsupported hash algorithm');
        }

        this.hashAlgorithm = hashAlgorithm;
        this.hLen = HASH_OCTET_LENGTHS.get(hashAlgorithm);
    }

    /**
     * @description EME-OAEP encoding
     * @see {@link https://tools.ietf.org/html/rfc8017#section-7.1.1}
     * @param message The message to encode.
     * @param k the length in octets of the encoded message (e.g. the size of the RSA modulus n).
     * @return The encoded message.
     */
    public Blob encode(Blob message, Integer k) {
        return this.encode(message, null, k);
    }

    /**
     * @description EME-OAEP encoding
     * @see {@link https://tools.ietf.org/html/rfc8017#section-7.1.1}
     * @param message The message to encode.
     * @param label An optional label to be associated with the message. Can be null.
     * @param k the length in octets of the encoded message (e.g. the size of the RSA modulus n).
     * @return The encoded message.
     */
    public Blob encode(Blob message, Blob label, Integer k) {
        if (message == null) {
            throw buildInvalidParamException('message', 'Message cannot be null');
        }

        if (k == null || k < 2 * this.hLen + 2) {
            throw buildInvalidParamException('k', 'K cannot be null or have an value lesser than the minimum encoded message size');
        }

        ByteBlob m = new ByteBlob(message);

        if (m.size() > k - 2 * this.hLen - 2) {
            throw buildInvalidParamException('message', 'Message too long');
        }

        ByteBlob l = label != null ? new ByteBlob(label) : new ByteBlob();

        ByteBlob seed = ByteBlob.fromRandomBytes(this.hLen);

        return encode(m, l, k, seed).toBlob();
    }

    @TestVisible
    @SuppressWarnings('PMD.ExcessiveParameterList')
    private ByteBlob encode(ByteBlob m, ByteBlob l, Integer k, ByteBlob seed) {
        ByteBlob lHash = generateDigest(l);

        ByteBlob ps = ByteBlob.fromZeroedBytes(k - m.size() - 2 * this.hLen - 2);

        // DB = lHash || PS || 0x01 || M
        ByteBlob db = ByteBlob.concat(new ByteBlob[] { lHash, ps, X01, m });

        ByteBlob dbMask = mgf1(seed, k - this.hLen - 1);

        ByteBlob maskedDb = db.xor(dbMask);

        ByteBlob seedMask = mgf1(maskedDb, this.hLen);

        ByteBlob maskedSeed = seed.xor(seedMask);

        // EM = 0x00 || maskedSeed || maskedDB
        return ByteBlob.concat(new ByteBlob[] { X00, maskedSeed, maskedDb });
    }

    /**
     * @description EME-OAEP decoding
     * @see {@link https://tools.ietf.org/html/rfc8017#section-7.1.2}
     * @param encodedMessage The message to decode.
     * @return The decoded message.
     */
    public Blob decode(Blob encodedMessage) {
        return this.decode(encodedMessage, EMPTY_BLOB);
    }

    /**
     * @description EME-OAEP decoding
     * @see {@link https://tools.ietf.org/html/rfc8017#section-7.1.2}
     * @param encodedMessage The message to decode.
     * @param label An optional label whose association with the message is to be verified. Can be null.
     * @return The decoded message.
     */
    public Blob decode(Blob encodedMessage, Blob label) {
        ByteBlob em = new ByteBlob(encodedMessage);

        validateEncodedMessage(em);

        ByteBlob l = new ByteBlob(label);

        ByteBlob db = decode(em, l);

        ByteBlob lHash = generateDigest(l);
        ByteBlob lHash2 = db.copyOfRange(0, this.hLen);
        
        if (!lHash.equals(lHash2)) {
            throw buildSecurityException();
        }

        Integer i01 = db.indexOf(1, this.hLen);
        if (i01 == -1) {
            throw buildSecurityException();
        }

        for (Integer i = this.hLen; i < i01; i++) {
            if (db.get(i) != 0) {
                throw buildSecurityException();
            }
        }

        ByteBlob m = db.copyOfRange(i01 + 1, db.size());

        return m.toBlob();
    }

    private void validateEncodedMessage(ByteBlob em) {
        Integer k = em.size();

        if (k < 2 * this.hLen + 2) {
            throw buildSecurityException();
        }

        Integer y = em.get(0);
        if (y != 0) {
            throw buildSecurityException();
        }
    }

    private ByteBlob decode(ByteBlob em, ByteBlob l) {
        Integer k = em.size();

        ByteBlob maskedSeed = em.copyOfRange(1, 1 + this.hLen);
        ByteBlob maskedDb = em.copyOfRange(1 + this.hLen, k);

        ByteBlob seedMask = mgf1(maskedDb, this.hLen);

        ByteBlob seed = maskedSeed.xor(seedMask);

        ByteBlob dbMask = mgf1(seed, k - this.hLen - 1);

        return maskedDb.xor(dbMask);
    }

    /**
     * @description MGF1 Mask Generation Function
     * @see {@link https://tools.ietf.org/html/rfc8017#appendix-B.2.1}
     * @param mgfSeed The seed from which mask is generated.
     * @param maskLen The intended length in octets of the mask, at most 2^32 hLen.
     * @return The mask of length maskLen.
     */
    @TestVisible
    private ByteBlob mgf1(ByteBlob mgfSeed, Integer maskLen) {
        ByteBlob t = new ByteBlob();

        Integer ceil = Math.ceil((Decimal)maskLen / this.hLen).intValue() - 1;

        for (Integer counter = 0; counter <= ceil; counter++) {
            ByteBlob c = i2osp4(counter);
            t.append(new ByteBlob[] { generateDigest(ByteBlob.concat(new ByteBlob[] { mgfSeed, c })) });
        }

        return t.copyOfRange(0, maskLen);
    }

    @TestVisible
    private ByteBlob generateDigest(ByteBlob byteBlob) {
        Blob digest = Crypto.generateDigest(this.hashAlgorithm, byteBlob.toBlob());
        return new ByteBlob(digest);
    }

    /**
     * @description I2OSP Integer to Octet String (32-bit specialization)
     * @see {@link https://tools.ietf.org/html/rfc8017#section-4.1}
     * @param x Nonnegative integer to be converted.
     * @return Corresponding octet string of length 4.
     */
    private static ByteBlob i2osp4(Integer x) {
        Integer[] bytes = new Integer[] {
            x >>> 24 & 255,
            x >>> 16 & 255,
            x >>> 8 & 255,
            x & 255
        };

        return ByteBlob.fromByteArray(bytes);
    }

    private static InvalidParameterValueException buildInvalidParamException(String paramName, String message) {
        InvalidParameterValueException ex = new InvalidParameterValueException(paramName, null);
        ex.setMessage(message);

        return ex;
    }

    private static SecurityException buildSecurityException() {
        return new SecurityException('Decryption error');
    }
}
