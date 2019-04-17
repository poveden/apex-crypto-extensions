/**
 * @description Byte array representation of a Blob.
 */
public class ByteBlob {
    private static final String HEX_DIGITS = '0123456789abcdef';

    @TestVisible
    private final List<Integer> bytes;

    /**
     * @description Initializes a new instance of the ByteBlob class, with empty contents.
     */
    public ByteBlob() {
        this(0);
    }

    private ByteBlob(Integer size) {
        this.bytes = new Integer[size];
    }

    /**
     * @description Initializes a new instance of the ByteBlob class, with the supplied blob as contents.
     * @param data The blob to be used as contents.
     */
    public ByteBlob(Blob data) {
        Integer n = data.size();
        this.bytes = new Integer[n];

        if (n == 0) {
            return;
        }

        String hex = EncodingUtil.convertToHex(data);

        Integer i = 0;
        Integer j = 0;

        while (i < n) {
            Integer b = nibbleAt(hex, j++) << 4 | nibbleAt(hex, j++);
            this.bytes[i++] = b;
        }
    }

    /**
     * @description Appends the provided blobs to the end of this instance.
     * @param blobs The blobs to append.
     */
    public void append(ByteBlob[] blobs) {
        if (blobs == null) {
            return;
        }

        for (ByteBlob b : blobs) {
            if (b != null) {
                this.bytes.addAll(b.bytes);
            }
        }
    }

    /**
     * @description Returns a value indicating whether the provided blob has the same contents as this instance.
     * @param other The blob to compare.
     * @return true if the provided blob has the same contents as this instance; otherwise, false.
     */
    public Boolean equals(ByteBlob other) {
        return other != null && this.bytes.equals(other.bytes);
    }

    /**
     * @description Returns the byte value at the specified index.
     * @param index The index of the byte to retrieve.
     * @return The byte's value.
     */
    public Integer get(Integer index) {
        return this.bytes[index];
    }

    /**
     * @description Returns the index of the first occurrence of the specified byte.
     * @param b The byte to search for.
     * @param startIndex The starting index to start the search from.
     * @return The index of the first occurrence of the specified byte, or -1 if it could not be found.
     */
    public Integer indexOf(Integer b, Integer startIndex) {
        for (Integer i = startIndex; i < this.bytes.size(); i++) {
            if (this.bytes[i] == b) {
                return i;
            }
        }

        return -1;
    }

    /**
     * @description Returns the size in bytes of this instance.
     * @return The size in bytes.
     */
    public Integer size() {
        return this.bytes.size();
    }

    /**
     * @description Creates a copy of a segment of this blob.
     * @param startIndex The zero-based start index.
     * @param endIndex The zero-based end index.
     * @return A new blob with the copied bytes.
     */
    public ByteBlob copyOfRange(Integer startIndex, Integer endIndex) {
        Integer n = endIndex - startIndex;

        if (n < 0) {
            throw buildInvalidParamException('endIndex', 'End index is lower than start index');
        }

        ByteBlob res = new ByteBlob(n);

        Integer i = 0;
        Integer j = startIndex;

        while (i < n) {
            res.bytes[i++] = this.bytes[j++];
        }

        return res;
    }

    /**
     * @description Creates a Blob object with the same contents as this instance.
     * @return The new blob.
     */
    public Blob toBlob() {
        String hex = this.toHexString();
        return EncodingUtil.convertFromHex(hex);
    }

    @TestVisible
    private String toHexString() {
        List<Integer> hexChars = new List<Integer>();

        for (Integer b : this.bytes) {
            Integer nibbleH = (b >>> 4) & 15;
            Integer nibbleL = b & 15;

            hexChars.add(HEX_DIGITS.charAt(nibbleH));
            hexChars.add(HEX_DIGITS.charAt(nibbleL));
        }

        return String.fromCharArray(hexChars);
    }

    /**
     * @description Performs a byte-per-byte XOR operation of this instance with another blob.
     * @param right The other blob to perform the XOR operation with.
     * @return The results of the XOR operation.
     */
    public ByteBlob xor(ByteBlob right) {
        Integer n = this.size();

        if (right.size() != n) {
            throw buildInvalidParamException('right', 'Argument value is not of the same size as this instance');
        }

        ByteBlob res = new ByteBlob(n);

        for (Integer i = 0; i < n; i++) {
            res.bytes[i] = this.bytes[i] ^ right.bytes[i];
        }

        return res;
    }

    /**
     * @description Concatenates the given blobs into a new blob.
     * @param blobs The blobs to concatenate.
     * @return The new blob.
     */
    public static ByteBlob concat(ByteBlob[] blobs) {
        ByteBlob res = new ByteBlob();

        res.append(blobs);

        return res;
    }

    /**
     * @description Creates a ByteBlob from the values of a Byte array.
     * @param byteArray The byte array to read the bytes from.
     * @return The resulting blob.
     */
    public static ByteBlob fromByteArray(Integer[] byteArray) {
        Integer n = byteArray.size();
        ByteBlob res = new ByteBlob(n);

        for (Integer i = 0; i < n; i++) {
            res.bytes[i] = byteArray[i] & 255;
        }

        return res;
    }

    /**
     * @description Returns a ByteBlob filled with random bytes.
     * @param numberOfBytes The number of random bytes to fill the ByteBlob with.
     * @return The resulting blob.
     */
    public static ByteBlob fromRandomBytes(Integer numberOfBytes) {
        ByteBlob res = new ByteBlob(numberOfBytes);

        Integer rnd;
        for (Integer i = 0; i < numberOfBytes; i++) {
            if (Math.mod(i, 4) == 0) {
                rnd = Crypto.getRandomInteger();
            }

            res.bytes[i] = rnd & 255;
            rnd >>>= 8;
        }

        return res;
    }

    /**
     * @description Returns a ByteBlob filled with zeroed (0x00) bytes.
     * @param numberOfBytes The number of zeroed bytes to fill the ByteBlob with.
     * @return The resulting blob.
     */
    public static ByteBlob fromZeroedBytes(Integer numberOfBytes) {
        ByteBlob res = new ByteBlob(numberOfBytes);

        for (Integer i = 0; i < numberOfBytes; i++) {
            res.bytes[i] = 0;
        }

        return res;
    }

    private static Integer nibbleAt(String str, Integer index) {
        Integer c = str.charAt(index);
        return HEX_DIGITS.indexOfChar(c);
    }

    private static InvalidParameterValueException buildInvalidParamException(String paramName, String message) {
        InvalidParameterValueException ex = new InvalidParameterValueException(paramName, null);
        ex.setMessage(message);

        return ex;
    }
}
