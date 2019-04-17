/**
 * @description An interface for a RSA padding scheme.
 */
public interface RsaPaddingScheme {
    /**
     * @description Encodes the given message.
     * @see {@link https://tools.ietf.org/html/rfc8017#section-7}
     * @param message The message to encode.
     * @param k the length in octets of the encoded message (e.g. the size of the RSA modulus n).
     * @return The encoded message.
     */
    Blob encode(Blob message, Integer k);

    /**
     * @description Decodes the given message.
     * @see {@link https://tools.ietf.org/html/rfc8017#section-7}
     * @param encodedMessage The message to decode.
     * @return The decoded message.
     */
    Blob decode(Blob encodedMessage);
}
