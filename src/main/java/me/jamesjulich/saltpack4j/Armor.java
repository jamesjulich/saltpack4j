package me.jamesjulich.saltpack4j;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.utils.Key;
import me.jamesjulich.saltpack4j.exception.SaltpackException;
import org.apache.commons.lang3.ArrayUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

public class Armor
{
    final String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    final char[] alphabetChars = alphabet.toCharArray();

    final BigInteger SIXTY_TWO = BigInteger.valueOf(62);

    Armor(){}

    public String armor(byte[] bytes, String messageType)
    {
        ArrayList<Byte[]> chunks = chunkByteArray(ArrayUtils.toObject(bytes), 32);
        String output = "";

        for (Byte[] chunk : chunks)
        {
            output += encodeBlock(chunk);
        }

        String result = "";
        for (int i = 0; i < output.length(); i++)
        {
            if (i % 15 == 0 && i != 0)
            {
                result += " ";
            }

            if (i % 3000 == 0 && i != 0)
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
        String[] parts = armoredString.split("\\.");

        if (!framingIsValid(parts))
        {
            throw new SaltpackException("Framing is invalid, cannot process armored string.");
        }

        String armored = parts[1];

        armored = armored.replaceAll("[>\\n\\r\\t ]", ""); //Strip all whitespaces.

        Character[] characterArr = ArrayUtils.toObject(armored.toCharArray());
        ArrayList<Character[]> chunks = chunkCharacterArray(characterArr, 43);

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
        String encodedString = ""; //The string will have to be reversed to make sure characters are ordered most sig to least sig.
        int charBlockLength = minimumCharBlockSize(bytes.length);

        for (int i = 0; i < charBlockLength; i++)
        {
            encodedString += letterFromNum(bytesInt.mod(SIXTY_TWO).intValue());
            bytesInt = bytesInt.divide(SIXTY_TWO);
        }
        return new StringBuilder(encodedString).reverse().toString();
    }

    //TODO look into making this a method that uses primitive chars.
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

    //Flashback to 10th grade algebra because Java doesn't provide a method in the Math class for this :\
    //...and I'm too lazy to look in other classes :P
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

    //Also another thing Java doesn't provide (that python does) by default.
    public static byte[] bigIntToByteArrayUnsigned(BigInteger bi, int byteArraySize) throws SaltpackException
    {
        byte[] extractedBytes = bi.toByteArray();
        int skipped = 0;
        boolean skip = true;
        for (byte b : extractedBytes)
        {
            boolean signByte = b == (byte) 0x00;
            if (skip && signByte)
            {
                skipped++;
                continue;
            }
            else if (skip)
            {
                skip = false;
            }
        }
        extractedBytes = Arrays.copyOfRange(extractedBytes, skipped, extractedBytes.length);

        if (extractedBytes.length > byteArraySize)
        {
            System.out.println("Houston, we have a problem.");
            System.out.println("Actual length: " + extractedBytes.length + " Wanted length: " + byteArraySize);
            System.out.println("Value of first byte: " + extractedBytes[0]);
            throw new SaltpackException("Could not convert BigInteger to byte[]: specified byte[] length too small. Got target length: " + byteArraySize + ", needed: " + extractedBytes.length);
        }

        if (extractedBytes.length < byteArraySize)
        {
            byte[] toAppend = new byte[byteArraySize - extractedBytes.length];
            extractedBytes = ArrayUtils.addAll(toAppend, extractedBytes);
        }
        return extractedBytes;
    }

    //TODO Merge these functions into a single function using generics.

    //Chunks a large array into a list of smaller arrays, the last array can be smaller than specified size.
    public ArrayList<Character[]> chunkCharacterArray(Character[] chunkyBoi, int size)
    {
        ArrayList<Character[]> chunks = new ArrayList<Character[]>();
        ArrayList<Character> currentChunk = new ArrayList<Character>();

        for (Character t : chunkyBoi)
        {
            currentChunk.add(t);

            if (currentChunk.size() == size)
            {
                chunks.add(currentChunk.toArray(new Character[currentChunk.size()]));
                currentChunk.clear();
            }
        }

        if (currentChunk.size() > 0)
        {
            chunks.add(currentChunk.toArray(new Character[currentChunk.size()]));
        }
        return chunks;
    }

    public static ArrayList<Byte[]> chunkByteArray(Byte[] chunkyBoi, int size)
    {
        ArrayList<Byte[]> chunks = new ArrayList<Byte[]>();
        ArrayList<Byte> currentChunk = new ArrayList<Byte>();

        for (Byte t : chunkyBoi)
        {
            currentChunk.add(t);

            if (currentChunk.size() == size)
            {
                chunks.add(currentChunk.toArray(new Byte[currentChunk.size()]));
                currentChunk.clear();
            }
        }

        if (currentChunk.size() > 0)
        {
            chunks.add(currentChunk.toArray(new Byte[currentChunk.size()]));
        }
        return chunks;
    }

    //TODO In the future, this will need to be changed to support streaming.
    private boolean framingIsValid(String[] parts)
    {
        //If the message doesnt contain two periods.
        if (parts.length != 3)
        {
            System.out.println("here");
            return false;
        }

        //If the frames don't match the provided regex.
        if (!parts[0].matches("^[>\\n\\r\\t ]*BEGIN[>\\n\\r\\t ]+([a-zA-Z0-9]+[>\\n\\r\\t ]+)?SALTPACK[>\\n\\r\\t ]+(ENCRYPTED[>\\n\\r\\t ]+MESSAGE|SIGNED[>\\n\\r\\t ]+MESSAGE|DETACHED[>\\n\\r\\t ]+SIGNATURE)[>\\n\\r\\t ]*$"))
        {
            System.out.println("nopehere");
            return false;
        }

        //If the beginning and end don't match (except the words BEGIN and END).
        parts[0] = parts[0].replaceFirst("BEGIN", "END");
        if (!parts[0].equals(parts[2].trim()))
        {
            System.out.println(parts[0]);
            System.out.println(parts[2]);
            System.out.println("HERE");
            return false;
        }
        return true;
    }
}
