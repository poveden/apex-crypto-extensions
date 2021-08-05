@IsTest
public class RsaPkcs1Encoder_Test {
    private static final TestVectors testVectors = new TestVectors();

    @IsTest
    public static void shouldBeAbleToEncodeAMessage() {
        RsaPkcs1Encoder pkcs1 = new RsaPkcs1Encoder();

        Blob em = pkcs1.encode(testVectors.M, testVectors.k);

        ByteBlob emb = new ByteBlob(em);

        System.assertEquals(0, emb.get(0));
        System.assertEquals(2, emb.get(1));
        System.assertEquals(0, emb.get(111));
        assertBlobEquals(testVectors.M, emb.copyOfRange(112, 128));
    }

    @IsTest
    public static void shouldBeAbleToDecodeAMessage() {
        RsaPkcs1Encoder pkcs1 = new RsaPkcs1Encoder();

        Blob m = pkcs1.decode(testVectors.EM);

        assertBlobEquals(testVectors.M, m);
    }

    @IsTest
    public static void shouldBeAbleToEncodeAndDecodeAMessage() {
        Integer k = 2048 / 8;
        RsaPkcs1Encoder pkcs1 = new RsaPkcs1Encoder();

        Blob message = Blob.valueOf('This is a test message');

        Blob encodedMessage = pkcs1.encode(message, k);
        Blob decodedMessage = pkcs1.decode(encodedMessage);

        assertBlobEquals(message, decodedMessage);
    }

    @IsTest
    public static void encodeShouldThrowOnANullMessage() {
        Integer k = 2048 / 8;
        RsaPkcs1Encoder pkcs1 = new RsaPkcs1Encoder();

        IllegalArgumentException caught = null;
        try {
            pkcs1.encode(null, k);
        } catch (IllegalArgumentException ex) {
            caught = ex;
        }

        System.assert(caught != null);
    }

    @IsTest
    public static void encodeShouldThrowOnANullOrInvalidK() {
        RsaPkcs1Encoder pkcs1 = new RsaPkcs1Encoder();

        Blob message = Blob.valueOf('This is a test message');
        Integer k = null;

        IllegalArgumentException caught = null;
        try {
            pkcs1.encode(message, k);
        } catch (IllegalArgumentException ex) {
            caught = ex;
        }

        System.assert(caught != null);

        k = 256 / 8;

        caught = null;
        try {
            pkcs1.encode(message, k);
        } catch (IllegalArgumentException ex) {
            caught = ex;
        }

        System.assert(caught != null);
    }

    @IsTest
    public static void encodeShouldThrowWhenTheMessageIsTooLong() {
        RsaPkcs1Encoder pkcs1 = new RsaPkcs1Encoder();

        Blob message = Blob.valueOf('This is too big a message to fit in the encoded message');
        Integer k = 512 / 8;

        IllegalArgumentException caught = null;
        try {
            pkcs1.encode(message, k);
        } catch (IllegalArgumentException ex) {
            caught = ex;
        }

        System.assert(caught != null);
    }

    @IsTest
    public static void decodeShouldThrowOnANullEncodedMessage() {
        RsaPkcs1Encoder pkcs1 = new RsaPkcs1Encoder();

        IllegalArgumentException caught = null;
        try {
            pkcs1.decode(null);
        } catch (IllegalArgumentException ex) {
            caught = ex;
        }

        System.assert(caught != null);
    }

    @IsTest
    public static void decodeShouldThrowOnAMalformedEncodedMessage() {
        RsaPkcs1Encoder pkcs1 = new RsaPkcs1Encoder();

        List<Blob> ems = new List<Blob> {
            forgeEncodedMessage(null, '12 34', null, '56 78'), // EM too short
            forgeEncodedMessage('01 02', null, null, null),    // EM[0] != 0x00
            forgeEncodedMessage('00 03', null, null, null),    // EM[1] != 0x02
            forgeEncodedMessage(null, null, '88', null)        // EM without x00 separator
        };

        for (Blob em : ems) {
            SecurityException caught = null;
            try {
                Blob m = pkcs1.decode(em);
            } catch (SecurityException ex) {
                caught = ex;
            }

            System.assert(caught != null);
            System.assertEquals('Decryption error', caught.getMessage());
        }
    }

    private static void assertBlobEquals(Blob expected, Blob actual) {
        System.assertEquals(EncodingUtil.convertToHex(expected), EncodingUtil.convertToHex(actual));
    }

    private static void assertBlobEquals(Blob expected, ByteBlob actual) {
        System.assertEquals(EncodingUtil.convertToHex(expected), actual.toHexString());
    }

    private static Blob forgeEncodedMessage(String x0002Hex, String psHex, String x00Hex, String mHex) {
        ByteBlob x0002 = blobOverride(fromHex('00 02'), x0002Hex);
        ByteBlob ps = blobOverride(testVectors.PS, psHex);
        ByteBlob x00 = blobOverride(fromHex('00'), x00Hex);
        ByteBlob m = blobOverride(testVectors.M, mHex);

        return ByteBlob.concat(new ByteBlob[] { x0002, ps, x00, m }).toBlob();
    }

    private static ByteBlob blobOverride(Blob defaultValue, String overrideValue) {
        if (overrideValue == null) {
            return new ByteBlob(defaultValue);
        }

        return new ByteBlob(fromHex(overrideValue));
    }

    private static Blob fromHex(String hex) {
        return EncodingUtil.convertFromHex(hex.remove(' '));
    }

    private class TestVectors {
        public final Integer k = 128; // 1024 bits of RSA modulus n

        /** M = Message to be encrypted */
        public final Blob M = fromHex(
            'd4 36 e9 95 69 fd 32 a7 c8 a0 5b bc 90 d3 2c 49'
        );

        public final Blob PS = fromHex(
            '50 b5 b2 d8 83 2d 3a 4a 87 b6 04 a5 4d 91 f6 e2 bb 8d f0 9b d2 a7 79 6d' +
            '72 23 59 09 83 5c 6a e2 ee f4 45 0f c0 e5 07 47 ba bd ae 3d 66 ff 50 55' +
            '10 c1 48 51 2f ab 76 e9 d1 9d 07 3a 8e cd 9b f7 aa 80 a5 76 91 e2 26 27' +
            '4d bd 0e fb 20 19 2d 23 73 69 86 5a eb 43 fc c5 ae 26 ff b4 7a 3e da 67' +
            '81 6e 95 aa 76 58 ea 0d cd e3 44 cc 19'
        );

        /** EM = 0x00 || 0x02 || PS || 0x00 || M */
        public final Blob EM = fromHex(
            '00 02 50 b5 b2 d8 83 2d 3a 4a 87 b6 04 a5 4d 91 f6 e2 bb 8d f0 9b d2 a7' +
            '79 6d 72 23 59 09 83 5c 6a e2 ee f4 45 0f c0 e5 07 47 ba bd ae 3d 66 ff' +
            '50 55 10 c1 48 51 2f ab 76 e9 d1 9d 07 3a 8e cd 9b f7 aa 80 a5 76 91 e2' +
            '26 27 4d bd 0e fb 20 19 2d 23 73 69 86 5a eb 43 fc c5 ae 26 ff b4 7a 3e' +
            'da 67 81 6e 95 aa 76 58 ea 0d cd e3 44 cc 19 00 d4 36 e9 95 69 fd 32 a7' +
            'c8 a0 5b bc 90 d3 2c 49'
        );
    }
}
