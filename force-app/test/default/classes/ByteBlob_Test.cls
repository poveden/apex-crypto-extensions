@IsTest
private class ByteBlob_Test {
    @IsTest
    static void shouldBeAbleToCreateAnEmptyByteBlob() {
        ByteBlob bb = new ByteBlob();

        System.assertEquals(0, bb.size());
    }

    @IsTest
    static void shouldBeAbleToCreateAByteBlobFromAnEmptyBlob() {
        Blob b = Blob.valueOf('');

        ByteBlob bb = new ByteBlob(b);

        System.assertEquals(0, bb.size());
    }

    @IsTest
    static void shouldBeAbleToCreateAByteBlobFromABlob() {
        String hex = 'ff00fe01fd02fc03';
        Blob b = EncodingUtil.convertFromHex(hex);
        ByteBlob bb = new ByteBlob(b);

        System.assertEquals(b.size(), bb.size());
        System.assertEquals(hex, bb.toHexString());
    }

    @IsTest
    static void shouldBeAbleToCreateAByteBlobFromAByteArray() {
        ByteBlob bb = ByteBlob.fromByteArray(new Integer[] { 1, 2, 3 });

        System.assertEquals(3, bb.size());
        System.assertEquals('010203', bb.toHexString());
    }

    @IsTest
    static void shouldBeAbleToCreateAByteBlobFromARandomSequenceOfBytes() {
        ByteBlob bb = ByteBlob.fromRandomBytes(2560);

        System.assertEquals(2560, bb.size());

        // We are not trying to assert Crypto.getRandomInteger(),
        // but only that we are indeed getting random bytes.
        Double randomness = (new Set<Integer>(bb.bytes)).size() / 256.0;
        System.assert(randomness > 0.9);
    }

    @IsTest
    public static void shouldBeAbleToCreateAByteBlobFromARandomSequenceOfNonZeroBytes() {
        ByteBlob bb = ByteBlob.fromRandomBytes(2560, true);

        System.assertEquals(2560, bb.size());

        System.assertEquals(-1, bb.indexOf(0, 0));
    }

    @IsTest
    static void shouldBeAbleToCreateAByteBlobFilledWithZeroedBytes() {
        ByteBlob bb = ByteBlob.fromZeroedBytes(10);

        System.assertEquals(10, bb.size());
        System.assertEquals('00000000000000000000', bb.toHexString());
    }

    @IsTest
    static void shouldBeAbleToAppendFromANullListOfBlobs() {
        ByteBlob bb = new ByteBlob();

        bb.append(null);

        System.assertEquals(0, bb.size());
    }

    @IsTest
    static void shouldBeAbleToAppendFromAListOfBlobs() {
        ByteBlob bb = new ByteBlob();

        bb.append(new ByteBlob[] {
            ByteBlob.fromByteArray(new Integer[] { 1, 2, 3 }),
            null,
            ByteBlob.fromByteArray(new Integer[] { 4, 5, 6 }),
            new ByteBlob(),
            ByteBlob.fromByteArray(new Integer[] { 7, 8, 9 })
        });

        System.assertEquals(9, bb.size());
        System.assertEquals('010203040506070809', bb.toHexString());
    }

    @IsTest
    static void equalsShouldReturnValidValues() {
        ByteBlob bb1 = ByteBlob.fromByteArray(new Integer[] { 1, 3, 5 });

        ByteBlob bb2 = ByteBlob.fromByteArray(new Integer[] { 1, 3, 5 });
        System.assert(bb1.equals(bb2));

        bb2 = ByteBlob.fromByteArray(new Integer[] { 1, 3, 5, 7 });
        System.assert(!bb1.equals(bb2));

        bb2 = ByteBlob.fromByteArray(new Integer[] { 1, 3 });
        System.assert(!bb1.equals(bb2));

        bb2 = ByteBlob.fromByteArray(new Integer[] { 2, 4, 6 });
        System.assert(!bb1.equals(bb2));

        System.assert(!bb1.equals(null));

        ByteBlob bb3 = new ByteBlob();
        System.assert(!bb3.equals(null));
    }

    @IsTest
    static void getShouldReturnValidValues() {
        Integer[] a = new Integer[] { 1, 3, 5, 7, 11, 13 };
        ByteBlob bb = ByteBlob.fromByteArray(a);

        for (Integer i = 0; i < 6; i++) {
            System.assertEquals(a[i], bb.get(i));
        }
    }

    @IsTest
    static void indexOfShouldReturnValidValues() {
        Integer[] a = new Integer[] { 1, 3, 5, 7, 1, 3 };
        ByteBlob bb = ByteBlob.fromByteArray(a);

        System.assertEquals(1, bb.indexOf(3, 0));
        System.assertEquals(5, bb.indexOf(3, 2));
        System.assertEquals(-1, bb.indexOf(3, 6));
    }

    @IsTest
    static void copyOfRangeShouldThrowOnInvalidRanges() {
        Integer[] a = new Integer[] { 2, 4, 6, 8, 10, 12, 14, 16 };
        ByteBlob bb1 = ByteBlob.fromByteArray(a);

        List<Integer[]> testRanges = new List<Integer[]> {
            new Integer[] { 0, 200 },
            new Integer[] { 8, 10 },
            new Integer[] { 7, 2 },
            new Integer[] { -1, 2 },
            new Integer[] { 0, null },
            new Integer[] { null, 8 }
        };

        for (Integer[] testRange : testRanges) {
            Exception caught = null;
            try {
                ByteBlob bb2 = bb1.copyOfRange(testRange[0], testRange[1]);
            } catch (ListException ex) {
                caught = ex;
            } catch (InvalidParameterValueException ex) {
                caught = ex;
            } catch (NullPointerException ex) {
                caught = ex;
            }

            System.assert(caught != null, String.format('Error: "{0}" - "{1}"', testRange));
        }
    }

    @IsTest
    static void copyOfRangeShouldReturnValidValues() {
        Integer[] a = new Integer[] { 2, 4, 6, 8, 10, 12, 14, 16 };
        ByteBlob bb1 = ByteBlob.fromByteArray(a);

        ByteBlob bb2 = bb1.copyOfRange(0, 8);
        System.assert(bb2.equals(bb1));

        bb2 = bb1.copyOfRange(0, 0);
        System.assert(bb2.equals(new ByteBlob()));

        bb2 = bb1.copyOfRange(2, 4);
        System.assert(bb2.equals(ByteBlob.fromByteArray(new Integer[] { 6, 8 })));

        bb2 = bb1.copyOfRange(1, 7);
        System.assert(bb2.equals(ByteBlob.fromByteArray(new Integer[] { 4, 6, 8, 10, 12, 14 })));
    }

    @IsTest
    static void toBlobShouldReturnValidValues() {
        String hex1 = 'ff00fe01fd02fc03';

        Blob b1 = EncodingUtil.convertFromHex(hex1);
        ByteBlob bb1 = new ByteBlob(b1);

        Blob b2 = bb1.toBlob();
        String hex2 = EncodingUtil.convertToHex(b2);

        System.assertEquals(hex1, hex2);
    }

    @IsTest
    static void concatShouldReturnValidValues() {
        List<integer> bla = new List<Integer>();
        List<integer> xxx = null;
        Boolean x = bla.equals(xxx);
        System.assertEquals(false, x);
        ByteBlob bb = ByteBlob.concat(null);
        System.assertEquals(0, bb.size());

        bb = ByteBlob.concat(new ByteBlob[] {
            ByteBlob.fromByteArray(new Integer[] { 1, 2, 3 }),
            null,
            ByteBlob.fromByteArray(new Integer[] { 4, 5, 6 }),
            new ByteBlob(),
            ByteBlob.fromByteArray(new Integer[] { 7, 8, 9 })
        });

        System.assertEquals(9, bb.size());
        System.assertEquals('010203040506070809', bb.toHexString());
    }

    @IsTest
    static void xorShouldThrowIfTheInputIsNullOrNotOfTheSameSize() {
        Integer[] a = new Integer[] { 2, 4, 6, 8, 10, 12, 14, 16 };
        ByteBlob left = ByteBlob.fromByteArray(a);

        List<ByteBlob> tests = new List<ByteBlob> {
            null,
            new ByteBlob(),
            ByteBlob.fromByteArray(new Integer[] { 1, 2, 3 })
        };

        for (ByteBlob right: tests) {
            Exception caught = null;
            try {
                ByteBlob res = left.xor(right);
            } catch (NullPointerException ex) {
                caught = ex;
            } catch (InvalidParameterValueException ex) {
                caught = ex;
            }

            System.assert(caught != null);
        }
    }

    @IsTest
    static void xorShouldReturnValidValues() {
        String hexLeft =  '00ffff';
        String hexRight = 'ff00ff';
        String expected = 'ffff00';

        ByteBlob left = new ByteBlob(EncodingUtil.convertFromHex(hexLeft));
        ByteBlob right = new ByteBlob(EncodingUtil.convertFromHex(hexRight));
        ByteBlob res = left.xor(right);

        System.assertEquals(expected, res.toHexString());
    }
}
