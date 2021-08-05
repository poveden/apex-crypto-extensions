/**
 * EME-PKCS1-v1_5 encoding/decoding for RSAES-PKCS1-v1_5 encryption scheme
 * @see {@link https://tools.ietf.org/html/rfc8017#section-7.2}
 */
public class RsaPkcs1Encoder implements RsaPaddingScheme {
    private final static ByteBlob x00 = ByteBlob.fromByteArray(new Integer[] { 0 });
    private final static ByteBlob x02 = ByteBlob.fromByteArray(new Integer[] { 2 });

    public RsaPkcs1Encoder() {
    }

    /**
     * EME-PKCS1-v1_5 encoding
     * @see {@link https://tools.ietf.org/html/rfc8017#section-7.2.1}
     * @param message The message to encode.
     * @param k The length in octets of the encoded message (e.g. the size of the RSA modulus n).
     * @returns The encoded message.
     */
    public Blob encode(Blob message, Integer k) {
        if (message == null) {
            throw new IllegalArgumentException('Message cannot be null');
        }

        if (k == null || k < 11) {
            throw new IllegalArgumentException('K cannot be null or have an value lesser than the minimum encoded message size');
        }

        ByteBlob m = new ByteBlob(message);

        if (m.size() > k - 11) {
            throw new IllegalArgumentException('Message too long');
        }

        ByteBlob ps = ByteBlob.fromRandomBytes(k - m.size() - 3, true);

        // EM = 0x00 || 0x02 || PS || 0x00 || M
        return ByteBlob.concat(new ByteBlob[] { x00, x02, ps, x00, m }).toBlob();
    }

    /**
     * EME-PKCS1-v1_5 decoding
     * @see {@link https://tools.ietf.org/html/rfc8017#section-7.2.2}
     * @param encodedMessage The message to decode.
     * @returns The decoded message.
     */
    public Blob decode(Blob encodedMessage) {
        if (encodedMessage == null) {
            throw new IllegalArgumentException('Encoded message cannot be null');
        }

        ByteBlob em = new ByteBlob(encodedMessage);

        if (em.size() < 11) {
            throw new SecurityException('Decryption error');
        }

        if (em.get(0) != 0) {
            throw new SecurityException('Decryption error');
        }

        if (em.get(1) != 2) {
            throw new SecurityException('Decryption error');
        }

        Integer i00 = em.indexOf(0, 2);
        if (i00 < 10) {
            throw new SecurityException('Decryption error');
        }

        ByteBlob ps = em.copyOfRange(i00 + 1, em.size());

        return ps.toBlob();
    }
}
