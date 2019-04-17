@IsTest
private class RsaOaepEncoder_Test {
    private static final TestVectors TEST_VECTORS = new TestVectors();

    @IsTest
    static void constructorShouldThrowOnANullHashAlgorithm() {
        InvalidParameterValueException caught = null;
        try {
            RsaOaepEncoder oaep = new RsaOaepEncoder(null);
        } catch (InvalidParameterValueException ex) {
            caught = ex;
        }

        System.assert(caught != null);
    }

    @IsTest
    static void constructorShouldThrowOnAnUnsupportedHashAlgorithm() {
        InvalidParameterValueException caught = null;
        try {
            RsaOaepEncoder oaep = new RsaOaepEncoder('MD5');
        } catch (InvalidParameterValueException ex) {
            caught = ex;
        }

        System.assert(caught != null);
    }

    @IsTest
    static void shouldBeAbleToEncodeAMessage() {
        RsaOaepEncoder oaep = new RsaOaepEncoder(TEST_VECTORS.hashAlgorithm);

        ByteBlob m = new ByteBlob(TEST_VECTORS.M);
        ByteBlob l = new ByteBlob(TEST_VECTORS.L);
        ByteBlob seed = new ByteBlob(TEST_VECTORS.seed);

        ByteBlob em = oaep.encode(m, l, TEST_VECTORS.k, seed);

        System.assert(blobEquals(TEST_VECTORS.EM, em));
    }

    @IsTest
    static void shouldBeAbleToDecodeAMessage() {
        RsaOaepEncoder oaep = new RsaOaepEncoder(TEST_VECTORS.hashAlgorithm);

        Blob m = oaep.decode(TEST_VECTORS.EM, TEST_VECTORS.L);

        System.assert(blobEquals(TEST_VECTORS.M, m));
    }

    @IsTest
    static void shouldBeAbleToEncodeAndDecodeAMessage() {
        Integer k = 2048 / 8;
        RsaOaepEncoder oaep = new RsaOaepEncoder('SHA1');

        Blob message = Blob.valueOf('This is a test message');

        Blob encodedMessage = oaep.encode(message, k);
        Blob decodedMessage = oaep.decode(encodedMessage);

        System.assert(blobEquals(message, decodedMessage));
    }

    @IsTest
    static void shouldBeAbleToEncodeAndDecodeAMessageWithALabel() {
        Integer k = 2048 / 8;
        RsaOaepEncoder oaep = new RsaOaepEncoder('SHA1');

        Blob message = Blob.valueOf('This is a test message');
        Blob label = Blob.valueOf('The label for the message');

        Blob encodedMessage = oaep.encode(message, label, k);
        Blob decodedMessage = oaep.decode(encodedMessage, label);

        System.assert(blobEquals(message, decodedMessage));
    }

    @IsTest
    static void encodeShouldThrowOnANullMessage() {
        Integer k = 2048 / 8;
        RsaOaepEncoder oaep = new RsaOaepEncoder('SHA1');

        InvalidParameterValueException caught = null;
        try {
            oaep.encode(null, k);
        } catch (InvalidParameterValueException ex) {
            caught = ex;
        }

        System.assert(caught != null);
    }

    @IsTest
    static void encodeShouldThrowOnANullOrInvalidK() {
        RsaOaepEncoder oaep = new RsaOaepEncoder('SHA1');

        Blob message = Blob.valueOf('This is a test message');
        Integer k = null;

        InvalidParameterValueException caught = null;
        try {
            oaep.encode(message, k);
        } catch (InvalidParameterValueException ex) {
            caught = ex;
        }

        System.assert(caught != null);

        k = 256 / 8;

        caught = null;
        try {
            oaep.encode(message, k);
        } catch (InvalidParameterValueException ex) {
            caught = ex;
        }

        System.assert(caught != null);
    }

    @IsTest
    static void encodeShouldThrowWhenTheMessageIsTooLong() {
        RsaOaepEncoder oaep = new RsaOaepEncoder('SHA1');

        Blob message = Blob.valueOf('This is too big a message to fit in the encoded message');
        Integer k = 512 / 8;

        InvalidParameterValueException caught = null;
        try {
            oaep.encode(message, k);
        } catch (InvalidParameterValueException ex) {
            caught = ex;
        }

        System.assert(caught != null);
    }

    @IsTest
    static void decodeShouldThrowOnANullEncodedMessage() {
        RsaOaepEncoder oaep = new RsaOaepEncoder('SHA1');

        NullPointerException caught = null;
        try {
            oaep.decode(null);
        } catch (NullPointerException ex) {
            caught = ex;
        }

        System.assert(caught != null);
    }

    @IsTest
    static void decodeShouldThrowOnAMalformedEncodedMessage() {
        RsaOaepEncoder oaep = new RsaOaepEncoder('SHA1');

        List<Blob> ems = new List<Blob> {
            forgeEncodedMessage(oaep, '112233', null), // EM too short
            forgeEncodedMessage(oaep, null, '01'),     // EM not starting with 0x00
            forgeEncodedMessage(oaep, '112233445566778899aabbccddeeff0011223344 000000 01 FFFFFF', null), // Invalid lHash
            forgeEncodedMessage(oaep, 'da39a3ee5e6b4b0d3255bfef95601890afd80709 000000 02 FFFFFF', null), // No x01 separator
            forgeEncodedMessage(oaep, 'da39a3ee5e6b4b0d3255bfef95601890afd80709 001100 01 FFFFFF', null)  // PS with non-zero bytes
        };

        for (Blob em : ems) {
            SecurityException caught = null;
            try {
                Blob m = oaep.decode(em);
            } catch (SecurityException ex) {
                caught = ex;
            }

            System.assert(caught != null);
            System.assertEquals('Decryption error', caught.getMessage());
        }
    }

    @IsTest
    static void encodingStepsShouldProduceCorrectValues() {
        RsaOaepEncoder oaep = new RsaOaepEncoder(TEST_VECTORS.hashAlgorithm);

        ByteBlob l = new ByteBlob(TEST_VECTORS.L);

        // lHash = Hash(L)
        ByteBlob lHash = oaep.generateDigest(l);
        System.assert(blobEquals(TEST_VECTORS.lHash, lHash));

        // dbMask = MGF(seed, k - hLen - 1)
        ByteBlob dbMask = oaep.mgf1(new ByteBlob(TEST_VECTORS.seed), TEST_VECTORS.k - TEST_VECTORS.hLen - 1);
        System.assert(blobEquals(TEST_VECTORS.dbMask, dbMask));

        // maskedDB = DB ⊕ dbMask
        ByteBlob maskedDb = (new ByteBlob(TEST_VECTORS.DB)).xor(dbMask);
        System.assert(blobEquals(TEST_VECTORS.maskedDb, maskedDb));

        // seedMask = MGF(maskedDB, hLen)
        ByteBlob seedMask = oaep.mgf1(maskedDb, TEST_VECTORS.hLen);
        System.assert(blobEquals(TEST_VECTORS.seedMask, seedMask));

        // maskedSeed = seed ⊕ seedMask
        ByteBlob maskedSeed = (new ByteBlob(TEST_VECTORS.seed)).xor(seedMask);
        System.assert(blobEquals(TEST_VECTORS.maskedSeed, maskedSeed));
    }

    private static Boolean blobEquals(Blob expected, Blob actual) {
        return EncodingUtil.convertToHex(expected) == EncodingUtil.convertToHex(actual);
    }

    private static Boolean blobEquals(Blob expected, ByteBlob actual) {
        return EncodingUtil.convertToHex(expected) == actual.toHexString();
    }

    private static Blob forgeEncodedMessage(RsaOaepEncoder oaep, String dbHex, String x00Hex) {
        ByteBlob seed = new ByteBlob(TEST_VECTORS.seed);

        ByteBlob x00 = blobOverride(fromHex('00'), x00Hex);

        ByteBlob db = blobOverride(TEST_VECTORS.DB, dbHex);
        ByteBlob dbMask = oaep.mgf1(seed, db.size());
        ByteBlob maskedDb = db.xor(dbMask);
        ByteBlob seedMask = oaep.mgf1(maskedDb, seed.size());
        ByteBlob maskedSeed = seed.xor(seedMask);

        return ByteBlob.concat(new ByteBlob[] { x00, maskedSeed, maskedDb }).toBlob();
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
        // References:
        // - https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf
        // - https://github.com/UniversaBlockchain/universa/blob/master/crypto/src/main/java/com/icodici/crypto/rsaoaep/RSAOAEPTestVectors.java
        // - https://github.com/pyca/cryptography/blob/master/vectors/cryptography_vectors/asymmetric/RSA/pkcs-1v2-1d2-vec/oaep-int.txt

        public final Integer k = 128; // 1024 bits of RSA modulus n
        
        public final String hashAlgorithm = 'SHA1';
        public final Integer hLen = 20; // 160 bits of SHA-1 hash

        /** M = Message to be encrypted */
        public final Blob M = fromHex(
            'd4 36 e9 95 69 fd 32 a7 c8 a0 5b bc 90 d3 2c 49'
        );

        /** L = Optional label */
        public final Blob L = fromHex(
            ''
        );

        /** lHash = Hash(L) */
        public final Blob lHash = fromHex(
            'da 39 a3 ee 5e 6b 4b 0d 32 55 bf ef 95 60 18 90 af d8 07 09'
        );

        /** DB = lHash || PS || 0x01 || M */
        public final Blob DB = fromHex(
            'da 39 a3 ee 5e 6b 4b 0d 32 55 bf ef 95 60 18 90 af d8 07 09 00 00 00 00' +
            '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
            '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
            '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 d4 36 e9 95 69' +
            'fd 32 a7 c8 a0 5b bc 90 d3 2c 49'
        );

        /** Test random seed */
        public final Blob seed = fromHex(
            'aa fd 12 f6 59 ca e6 34 89 b4 79 e5 07 6d de c2 f0 6c b5 8f'
        );

        /** dbMask = MGF(seed, k - hLen - 1) */
        public final Blob dbMask = fromHex(
            '06 e1 de b2 36 9a a5 a5 c7 07 d8 2c 8e 4e 93 24 8a c7 83 de e0 b2 c0 46' +
            '26 f5 af f9 3e dc fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c dc fe 4f f4' +
            '77 28 b4 a1 b7 c1 36 2b aa d2 9a b4 8d 28 69 d5 02 41 21 43 58 11 59 1b' +
            'e3 92 f9 82 fb 3e 87 d0 95 ae b4 04 48 db 97 2f 3a c1 4e af f4 9c 8c 3b' +
            '7c fc 95 1a 51 ec d1 dd e6 12 64'
        );

        /** maskedDB = DB ⊕ dbMask */
        public final Blob maskedDb = fromHex(
            'dc d8 7d 5c 68 f1 ee a8 f5 52 67 c3 1b 2e 8b b4 25 1f 84 d7 e0 b2 c0 46' +
            '26 f5 af f9 3e dc fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c dc fe 4f f4' +
            '77 28 b4 a1 b7 c1 36 2b aa d2 9a b4 8d 28 69 d5 02 41 21 43 58 11 59 1b' +
            'e3 92 f9 82 fb 3e 87 d0 95 ae b4 04 48 db 97 2f 3a c1 4f 7b c2 75 19 52' +
            '81 ce 32 d2 f1 b7 6d 4d 35 3e 2d'
        );

        /** seedMask = MGF(maskedDB, hLen) */
        public final Blob seedMask = fromHex(
            '41 87 0b 5a b0 29 e6 57 d9 57 50 b5 4c 28 3c 08 72 5d be a9'
        );

        /** maskedSeed = seed ⊕ seedMask */
        public final Blob maskedSeed = fromHex(
            'eb 7a 19 ac e9 e3 00 63 50 e3 29 50 4b 45 e2 ca 82 31 0b 26'
        );

        /** EM = 0x00 || maskedSeed || maskedDB */
        public final Blob EM = fromHex(
            '00 eb 7a 19 ac e9 e3 00 63 50 e3 29 50 4b 45 e2 ca 82 31 0b 26 dc d8 7d' +
            '5c 68 f1 ee a8 f5 52 67 c3 1b 2e 8b b4 25 1f 84 d7 e0 b2 c0 46 26 f5 af' +
            'f9 3e dc fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c dc fe 4f f4 77 28 b4' +
            'a1 b7 c1 36 2b aa d2 9a b4 8d 28 69 d5 02 41 21 43 58 11 59 1b e3 92 f9' +
            '82 fb 3e 87 d0 95 ae b4 04 48 db 97 2f 3a c1 4f 7b c2 75 19 52 81 ce 32' +
            'd2 f1 b7 6d 4d 35 3e 2d'
        );
    }
}
