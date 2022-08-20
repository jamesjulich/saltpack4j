package me.jamesjulich.saltpack4j;

import me.jamesjulich.saltpack4j.exception.SaltpackException;
import org.apache.commons.lang3.ArrayUtils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

public class Armor
{
    final String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    final char[] alphabetChars = alphabet.toCharArray();

    final BigInteger SIXTY_TWO = BigInteger.valueOf(62);

    Armor(){}

    /**
     * Produces an armored String from an array of bytes
     * @param bytes the source bytes
     * @param messageType the message type string that appears in the beginning and end of an armored string
     * @return
     */
    public String armor(byte[] bytes, String messageType)
    {
        ArrayList<Byte[]> chunks = SaltpackUtil.chunkArray(ArrayUtils.toObject(bytes), 32);
        String output = "";

        for (Byte[] chunk : chunks)
        {
            output += encodeBlock(chunk);
        }

        String result = "";
        for (int i = 0; i < output.length(); i++)
        {
            if (i % 15 == 0 && i != 0) // add spaces every fifteen characters
            {
                result += " ";
            }

            if (i % 3000 == 0 && i != 0) // add a line break every 3000 characters
            {
                result += "\n";
            }
            result += output.charAt(i);
        }
        String header = "BEGIN SALTPACK " + messageType + ". ";
        String footer = ". END SALTPACK " + messageType + ".";
        return header + result + footer;
    }

    public byte[] dearmor(String armoredString) throws SaltpackException
    {
        String[] parts = armoredString.trim().split("\\.");

        if (!framingIsValid(parts))
        {
            throw new SaltpackException("Framing is invalid, cannot process armored string.");
        }

        String armored = parts[1];

        armored = armored.replaceAll("[>\\n\\r\\t ]", ""); // Strip all whitespaces.

        Character[] characterArr = ArrayUtils.toObject(armored.toCharArray());
        ArrayList<Character[]> chunks = SaltpackUtil.chunkArray(characterArr, 43);

        ArrayList<Byte> bytes = new ArrayList<>();

        for (Character[] cA : chunks)
        {
            for (Byte b : decodeBlock(cA))
            {
                bytes.add(b);
            }
        }
        return ArrayUtils.toPrimitive(bytes.toArray(new Byte[bytes.size()]));
    }

    public String encodeBlock(Byte[] bytes)
    {
        BigInteger bytesInt = new BigInteger(1, ArrayUtils.toPrimitive(bytes));
        StringBuilder encodedString = new StringBuilder();

        int charBlockLength = minimumCharBlockSize(bytes.length);

        for (int i = 0; i < charBlockLength; i++)
        {
            encodedString.append(letterFromNum(bytesInt.mod(SIXTY_TWO).intValue()));
            bytesInt = bytesInt.divide(SIXTY_TWO);
        }

        // The String is reversed to order the characters from most significant to least significant.
        return new StringBuilder(encodedString.toString()).reverse().toString();
    }

    public byte[] decodeBlock(Character[] chars) throws SaltpackException
    {
        BigInteger decodedInt = BigInteger.valueOf(numFromLetter(chars[0]));

        if (chars.length > 1)
        {
            for (int i = 1; i < chars.length; i++)
            {
                decodedInt = decodedInt.multiply(SIXTY_TWO);
                decodedInt = decodedInt.add(BigInteger.valueOf(numFromLetter(chars[i])));
            }
        }
        return bigIntToByteArrayUnsigned(decodedInt, maxBytesBlockSize(chars.length));
    }

    public char letterFromNum(int i)
    {
        return alphabetChars[i];
    }

    public int numFromLetter(char c)
    {
        return alphabet.indexOf(c);
    }

    private double log(int n, int b)
    {
        return (Math.log(n) / Math.log(b));
    }

    public int minimumCharBlockSize(int bytesLength)
    {
        return (int) Math.round(Math.ceil(8.0 * bytesLength / log(62, 2)));
    }

    public int maxBytesBlockSize(int charsLength)
    {
        return (int) Math.round(Math.floor(log(62, 2) / 8.0 * charsLength));
    }

    /**
     * Removes the most significant byte (the first byte) if it serves only as a positive sign byte.
     * Adds padding to the front of the resulting array to create a byte array with the specified
     * length.
     * @param bi a BigInteger object
     * @param byteArraySize the size of the byte array to fit the integer into
     * @return a byte array containing optional padding and the byte representation of the BigInteger
     * @throws SaltpackException if 'byteArraySize' < minimum bytes needed to represent 'bi'
     */
    public static byte[] bigIntToByteArrayUnsigned(BigInteger bi, int byteArraySize) throws SaltpackException
    {
        byte[] extractedBytes = bi.toByteArray();
        boolean skipFirst = extractedBytes[0] == 0;

        // If skipping the first byte, drop the first byte.
        if (skipFirst)
            extractedBytes = Arrays.copyOfRange(extractedBytes, 1, extractedBytes.length);

        if (extractedBytes.length > byteArraySize)
        {
            throw new SaltpackException("Could not convert BigInteger to byte[]: specified byte[] length too small. Got target length: " + byteArraySize + ", needed: " + extractedBytes.length);
        }

        if (extractedBytes.length < byteArraySize)
        {
            byte[] toAppend = new byte[byteArraySize - extractedBytes.length];
            extractedBytes = ArrayUtils.addAll(toAppend, extractedBytes);
        }
        return extractedBytes;
    }

    // TODO In the future, this will need to be changed to support streaming.
    private boolean framingIsValid(String[] parts)
    {
        // If the message doesn't contain two periods.
        if (parts.length != 3)
        {
            return false;
        }

        // If the frames don't match the provided regex.
        if (!parts[0].matches("^[>\\n\\r\\t ]*BEGIN[>\\n\\r\\t ]+([a-zA-Z0-9]+[>\\n\\r\\t ]+)?SALTPACK[>\\n\\r\\t ]+(ENCRYPTED[>\\n\\r\\t ]+MESSAGE|SIGNED[>\\n\\r\\t ]+MESSAGE|DETACHED[>\\n\\r\\t ]+SIGNATURE)[>\\n\\r\\t ]*$"))
        {
            return false;
        }

        // If the beginning and end don't match (except the words BEGIN and END).
        parts[0] = parts[0].replaceFirst("BEGIN", "END");
        return parts[0].equals(parts[2].trim());
    }
}
