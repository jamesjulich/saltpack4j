package me.jamesjulich.saltpack4j;

import com.goterl.lazysodium.LazySodium;
import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Box;
import com.goterl.lazysodium.interfaces.SecretBox;
import com.goterl.lazysodium.utils.Key;
import me.jamesjulich.saltpack4j.exception.SaltpackException;
import org.apache.commons.lang3.ArrayUtils;
import org.msgpack.core.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

public class Encrypt
{
    final static int MAJOR_VERSION = 2;
    final static int MINOR_VERSION = 0;
    final static int MODE = 0;

    final static String SENDER_KEY_SBOX_NONCE = "saltpack_sender_key_sbox";
    final static String PAYLOAD_KEY_BOX_NONCE_V1 = "saltpack_payload_key_box";
    final static String PAYLOAD_KEY_BOX_NONCE_V2 = "saltpack_recipsb";
    final static String PAYLOAD_NONCE_PREFIX = "saltpack_ploadsb";

    final static String myPubKey = "0121e188d25594c9315e78065ab9331bbc3590de83c5ae9d93e445754547b86905720a";

    private final LazySodium sodiumInstance;

    Encrypt(LazySodium sodiumInstance)
    {
        this.sodiumInstance = sodiumInstance;
    }

    private byte[] getPayloadKeyBoxNonce(int majorVersion, long recipIndex) throws SaltpackException
    {
        if (majorVersion == 1)
            return PAYLOAD_KEY_BOX_NONCE_V1.getBytes();
        else
            return ArrayUtils.addAll(PAYLOAD_KEY_BOX_NONCE_V2.getBytes(), Armor.bigIntToByteArrayUnsigned(BigInteger.valueOf(recipIndex), 8));
    }

    private ArrayList<Byte[]> chunksWithEmpty(Byte[] toChunk, int chunkSize)
    {
        ArrayList<Byte[]> chunked = SaltpackUtil.chunkArray(toChunk, chunkSize);
        chunked.add(new Byte[]{});
        return chunked;
    }

    private byte[] generatePayloadHash(byte[] headerHash, byte[] payloadNonce, boolean finalFlag, byte[] payloadSecretBox, int majorVersion)
    {
        byte[] finalFlagByte;
        if (majorVersion == 2)
        {
            finalFlagByte = new byte[]{finalFlag ? (byte) 0x01 : (byte) 0x00};
        }
        else
        {
            finalFlagByte = new byte[0];
        }
        byte[] concat = concat = ArrayUtils.addAll(ArrayUtils.addAll(ArrayUtils.addAll(headerHash, payloadNonce), finalFlagByte), payloadSecretBox);
        byte[] hash = new byte[64];
        sodiumInstance.cryptoHashSha512(hash, concat, concat.length);
        return hash;
    }

    // Mode 0 = encryption, mode 1 = decryption.
    // This is slightly convoluted, but it prevents a LOT of code reuse.
    private byte[] generateMACKey(byte[] key1, byte[] key2, byte[] key3, byte[] headerHash, long recipientIndex, int majorVersion, int mode) throws SaltpackException
    {
        if (mode != 0 && mode != 1)
        {
            throw new SaltpackException("Invalid MAC key generation mode.");
        }

        if (majorVersion == 1)
        {
            /*
                key3 is not needed for this version.

                if mode == 0
                key1 = recip public
                key2 = sender private

                if mode == 1
                key1 = sender public
                key2 = recip private
             */

            byte[] headerHashFirstBytes = new byte[24];
            System.arraycopy(headerHash, 0, headerHashFirstBytes, 0, 24); // Copy first 24 bytes of header hash.

            byte[] macKeyBox = new byte[Box.MACBYTES + 32];
            sodiumInstance.cryptoBoxEasy(macKeyBox, new byte[32], 32, headerHashFirstBytes, key1, key2);

            byte[] macKey = new byte[32];
            System.arraycopy(macKeyBox, macKeyBox.length - 32, macKey, 0, 32);

            return macKey;
        }
        else if (majorVersion == 2) // TODO Needs to be double checked using Go implementation.
        {
            /*
                if mode == 0
                key1 = recip public
                key2 = sender private
                key3 = ephemeral private

                if mode == 1
                key1 = sender public
                key2 = recip private
                key3 = ephemeral public
             */

            byte[] headerHashFirstBytes = new byte[16];
            System.arraycopy(headerHash, 0, headerHashFirstBytes, 0, 16); // Copy the first 16 bytes of header hash to this array.

            byte[] indexBytes = Armor.bigIntToByteArrayUnsigned(BigInteger.valueOf(recipientIndex), 8);

            byte[] nonceBase = ArrayUtils.addAll(headerHashFirstBytes, indexBytes);
            nonceBase[15] &= 0xfe; // Clear the least significant bit at index 15.

            byte[] macKeyBoxLongTermKey = new byte[Box.MACBYTES + 32];
            sodiumInstance.cryptoBoxEasy(macKeyBoxLongTermKey, new byte[32], 32, nonceBase, key1, key2); // encrypt 32 zero bytes

            nonceBase[15] |= 0x01; // Set least significant bit of byte at index 15.

            byte[] macKeyBoxEphemeralKey = new byte[Box.MACBYTES + 32];
            sodiumInstance.cryptoBoxEasy(macKeyBoxEphemeralKey, new byte[32], 32, nonceBase,
                    (mode == 0 ) ? key1 : key3,
                    (mode == 0) ? key3 : key2); // encrypt 32 zero bytes again, with different keys

            byte[] concat = new byte[64];
            System.arraycopy(macKeyBoxLongTermKey, macKeyBoxLongTermKey.length - 32, concat, 0, 32); // Copy first 32 to indicies 0-31
            System.arraycopy(macKeyBoxEphemeralKey, macKeyBoxEphemeralKey.length - 32, concat, 32, 32); // Copy first 32 to indicies 32-63

            byte[] macKeyHash = new byte[64];
            sodiumInstance.cryptoHashSha512(macKeyHash, concat, 64); // Take SHA-512 hash of the above bytes

            byte[] macKey = new byte[32];
            System.arraycopy(macKeyHash, 0, macKey, 0, 32); // Copy first 32 bytes of hash to macKey

            return macKey;
        }
        else
        {
            throw new SaltpackException("Invalid/unsupported major version ' " + majorVersion + "'.");
        }
    }

    /**
     * Encrypts an array of bytes using the Saltpack secure messaging format
     * @param message the payload to encrypt
     * @param recipientList an array of public keys encoded as byte arrays
     * @param privKey the sender's private key
     * @param majorVersion the version of Saltpack to encrypt with
     * @param senderVisible true = send anonymously, false = not anonymously
     * @param recipientsVisible true = recipients can view other recipients
     * @param out a stream of encrypted bytes
     */
    public void encrypt(byte[] message, byte[][] recipientList, byte[] privKey, int majorVersion, boolean senderVisible, boolean recipientsVisible, ByteArrayOutputStream out) throws IOException, SodiumException, SaltpackException
    {
        if (majorVersion != 1 && majorVersion != 2)
        {
            throw new SaltpackException("Unsupported saltpack version. Expected major version 1 or 2, got '" + majorVersion + "'.");
        }

        MessageBufferPacker headerPacker = MessagePack.newDefaultBufferPacker();
        SecureRandom sr = new SecureRandom();

        byte[] senderPublic = sodiumInstance.cryptoScalarMultBase(Key.fromBytes(privKey)).getAsBytes();
        byte[] ephemeralPrivate = new byte[32];
        sr.nextBytes(ephemeralPrivate);
        byte[] ephemeralPublic = sodiumInstance.cryptoScalarMultBase(Key.fromBytes(ephemeralPrivate)).getAsBytes();
        byte[] payloadKey = new byte[32];
        sr.nextBytes(payloadKey);

        byte[] senderSbox = new byte[SecretBox.MACBYTES + senderPublic.length];
        sodiumInstance.cryptoSecretBoxEasy(senderSbox, (senderVisible) ? senderPublic : ephemeralPublic, (senderVisible) ? senderPublic.length : ephemeralPublic.length, SENDER_KEY_SBOX_NONCE.getBytes(), payloadKey);

        // This is the first part of the header. The next block of code writes recipients to the header.
        headerPacker.packArrayHeader(6);
        headerPacker.packString("saltpack");
        headerPacker.packArrayHeader(2); // Create an array with 2 elements.
        headerPacker.packInt(majorVersion);
        headerPacker.packInt((majorVersion != 1) ? MINOR_VERSION : 0); // This concludes the array.
        headerPacker.packInt(MODE);
        headerPacker.packBinaryHeader(ephemeralPublic.length);
        headerPacker.writePayload(ephemeralPublic);
        headerPacker.packBinaryHeader(senderSbox.length);
        headerPacker.writePayload(senderSbox);

        headerPacker.packArrayHeader(recipientList.length);
        for (int i = 0; i < recipientList.length; i++)
        {
            byte[] recipient = recipientList[i];
            byte[] payloadKeyBox = new byte[payloadKey.length + Box.MACBYTES];
            sodiumInstance.cryptoBoxEasy(payloadKeyBox, payloadKey, payloadKey.length, getPayloadKeyBoxNonce(majorVersion, i), recipient, ephemeralPrivate);

            headerPacker.packArrayHeader(2);
            if (recipientsVisible)
            {
                headerPacker.packBinaryHeader(recipient.length);
                headerPacker.writePayload(recipient);
            }
            else
            {
                headerPacker.packNil();
            }
            headerPacker.packBinaryHeader(payloadKeyBox.length);
            headerPacker.writePayload(payloadKeyBox);
        }

        // Now that header is finished being written, write to byte array for encoding again.
        byte[] headerBytes = headerPacker.toByteArray();
        byte[] headerHash = new byte[64];
        sodiumInstance.cryptoHashSha512(headerHash, headerBytes, headerBytes.length); // SHA512 header into headerHash

        // Double-encode the header bytes to make decryption easier
        MessageBufferPacker messagePacker = MessagePack.newDefaultBufferPacker();
        messagePacker.packBinaryHeader(headerBytes.length);
        messagePacker.writePayload(headerBytes);

        for (byte b : messagePacker.toByteArray())
        {
            out.write(b);
        }
        messagePacker.clear();

        byte[][] recipientMacKeys = new byte[recipientList.length][32];
        for (int i = 0; i < recipientList.length; i++)
        {
            byte[] recipient = recipientList[i];
            if (majorVersion == 1)
            {
                recipientMacKeys[i] = generateMACKey(recipient, privKey, null, headerHash, i, majorVersion, 0);
            }
            else if (majorVersion == 2)
            {
                recipientMacKeys[i] = generateMACKey(recipient, privKey, ephemeralPrivate, headerHash, i, majorVersion, 0);
            }
        }

        // TODO Support streaming by continuing to chunk in a while loop until input stream is closed.
        ArrayList<Byte[]> chunks = chunksWithEmpty(ArrayUtils.toObject(message), 1000000); // Chunk message into 1MB parts.
        for (int i = 0; i < chunks.size(); i++)
        {
            Byte[] currentChunk = chunks.get(i);
            byte[] payloadNonce = ArrayUtils.addAll(PAYLOAD_NONCE_PREFIX.getBytes(), Armor.bigIntToByteArrayUnsigned(BigInteger.valueOf(i), 8));
            byte[] payloadSecretBox = new byte[SecretBox.MACBYTES + currentChunk.length];
            sodiumInstance.cryptoSecretBoxEasy(payloadSecretBox, ArrayUtils.toPrimitive(currentChunk), currentChunk.length, payloadNonce, payloadKey);
            byte[] payloadHash = generatePayloadHash(headerHash, payloadNonce, currentChunk.length == 0, payloadSecretBox, majorVersion);

            messagePacker.packArrayHeader((majorVersion == 2) ? 3 : 2); // 3 value array for V2, 2 values for V1.

            if (majorVersion == 2)
            {
                messagePacker.packBoolean(currentChunk.length == 0);
            }

            messagePacker.packArrayHeader(recipientList.length);
            for (byte[] macKey : recipientMacKeys)
            {
                byte[] hmac = new byte[64];
                sodiumInstance.cryptoAuthHMACSha512(hmac, payloadHash, payloadHash.length, macKey);
                byte[] hmac32 = new byte[32];
                System.arraycopy(hmac, 0, hmac32, 0, 32);
                messagePacker.packBinaryHeader(hmac32.length);
                messagePacker.writePayload(hmac32);
            }
            messagePacker.packBinaryHeader(payloadSecretBox.length);
            messagePacker.writePayload(payloadSecretBox);
            out.write(messagePacker.toByteArray());
            messagePacker.clear();
        }
    }

    /**
     * Decrypts bytes using the Saltpack secure messaging format
     * @param cipherText the bytes to decrypt
     * @param privKey the recipient's private key
     * @param out a stream of bytes that outputs a decrypted payload
     */
    public void decrypt(byte[] cipherText, byte[] privKey, ByteArrayOutputStream out) throws IOException, SaltpackException
    {
        try
        {
            Armor a = new Armor();

            MessageUnpacker messageUnpacker = MessagePack.newDefaultUnpacker(cipherText);

            byte[] encodedHeader = new byte[messageUnpacker.unpackBinaryHeader()];
            messageUnpacker.readPayload(encodedHeader);

            byte[] headerHash = new byte[64]; // SHA-512 hash = 512 bits = 64 bytes.
            sodiumInstance.cryptoHashSha512(headerHash, encodedHeader, encodedHeader.length);

            MessageUnpacker headerUnpacker = MessagePack.newDefaultUnpacker(encodedHeader);

            int headerItems = headerUnpacker.unpackArrayHeader();

            if (headerItems < 6)
            {
                throw new SaltpackException("Invalid saltpack header. Header does not contain contents necessary to process message.");
            }

            String messageFormat = headerUnpacker.unpackString();
            if (!messageFormat.equals("saltpack"))
            {
                throw new SaltpackException("Expected message format 'saltpack', got '" + messageFormat + "'. Message unintended for saltpack?");
            }

            headerUnpacker.unpackArrayHeader(); // Version array

            int majorVersion = headerUnpacker.unpackInt();
            int minorVersion = headerUnpacker.unpackInt();

            if (majorVersion != 1 && majorVersion != 2)
            {
                throw new SaltpackException("Unsupported saltpack major version found. Either saltpack4j is out of date (most likely) or the message is malformed.");
            }

            int mode = headerUnpacker.unpackInt();
            if (mode != 0)
            {
                throw new SaltpackException("Saltpack message is not an encrypted message. Expected mode 0, got mode " + mode + ". See saltpack.org for more details on saltpack modes.");
            }

            byte[] ephemeralPubKey = new byte[headerUnpacker.unpackBinaryHeader()];
            headerUnpacker.readPayload(ephemeralPubKey);

            // String sharedSecret = sodiumInstance.cryptoBoxBeforeNm(ephemeralPubKey, privKey);
            byte[] sharedSecret = new byte[48];
            sodiumInstance.cryptoBoxBeforeNm(sharedSecret, ephemeralPubKey, privKey);

            byte[] senderSbox = new byte[headerUnpacker.unpackBinaryHeader()];
            headerUnpacker.readPayload(senderSbox);

            int recipientsNum = headerUnpacker.unpackArrayHeader();

            int currentRecipNumber = 0;
            byte[] payloadKey = null;
            while (currentRecipNumber < recipientsNum)
            {
                int recipEntryLength = headerUnpacker.unpackArrayHeader();
                if (headerUnpacker.getNextFormat() == MessageFormat.NIL) // If recipients are anonymous
                {
                    headerUnpacker.unpackNil();
                }
                else
                {
                    headerUnpacker.readPayload(headerUnpacker.unpackBinaryHeader());// TODO Add known recipients to saltpack message class.
                }

                byte[] payloadKeyBox = new byte[headerUnpacker.unpackBinaryHeader()];
                headerUnpacker.readPayload(payloadKeyBox);

                payloadKey = new byte[32];

                if (!sodiumInstance.cryptoBoxOpenEasyAfterNm(payloadKey, payloadKeyBox, payloadKeyBox.length, getPayloadKeyBoxNonce(majorVersion, currentRecipNumber), sharedSecret))
                {
                    currentRecipNumber++;
                    continue;
                }
                break; // If there is no error, break from the loop to signify that a match was found.
            }

            // If we aren't able to access the payload key box.
            if (currentRecipNumber >= recipientsNum)
            {
                throw new SaltpackException("Private key could not decrypt message. Are you using the wrong key?");
            }

            byte[] senderKey = new byte[32];
            sodiumInstance.cryptoSecretBoxOpenEasy(senderKey, senderSbox, senderSbox.length, SENDER_KEY_SBOX_NONCE.getBytes(), payloadKey);

            byte[] macKey = generateMACKey(senderKey, privKey, ephemeralPubKey, headerHash, 0, majorVersion, 1);

            BigInteger currentChunk = BigInteger.valueOf(0);

            // And now for the fun part, actually decrypting things :P
            while (true)
            {
                boolean finalFlag = false;

                messageUnpacker.unpackArrayHeader(); // Unpack the array header for the payload packet.

                if (majorVersion == 2)
                {
                    finalFlag = messageUnpacker.unpackBoolean();
                }

                int numAuthenticators = messageUnpacker.unpackArrayHeader();

                byte[][] authenticators = new byte[numAuthenticators][32];
                byte[] ourAuthenticator = authenticators[currentRecipNumber];
                byte[] payloadNonce = ArrayUtils.addAll(PAYLOAD_NONCE_PREFIX.getBytes(), Armor.bigIntToByteArrayUnsigned(currentChunk, 8));

                for (int i = 0; i < recipientsNum; i++)
                {
                    messageUnpacker.unpackBinaryHeader();
                    messageUnpacker.readPayload(authenticators[i]); // TODO Optimize to skip all remaining authenticators before/after ours is read.
                }

                byte[] encryptedPayload = new byte[messageUnpacker.unpackBinaryHeader()];
                messageUnpacker.readPayload(encryptedPayload);
                byte[] payloadHash = generatePayloadHash(headerHash, payloadNonce, finalFlag, encryptedPayload, majorVersion);
                byte[] hmac = new byte[64];
                sodiumInstance.cryptoAuthHMACSha512(hmac, payloadHash, payloadHash.length, macKey);
                byte[] hmac32 = new byte[32];
                System.arraycopy(hmac, 0, hmac32, 0, 32);

                if (!Arrays.equals(ourAuthenticator, hmac32))
                {
                    throw new SaltpackException("Invalid HMAC authenticator. Could not verify authenticity of payload #" + currentChunk.toString());
                }

                byte[] decryptedPayload = new byte[encryptedPayload.length - SecretBox.MACBYTES];
                sodiumInstance.cryptoSecretBoxOpenEasy(decryptedPayload, encryptedPayload, encryptedPayload.length, payloadNonce, payloadKey);

                for (byte b : decryptedPayload)
                {
                    out.write(b);
                }

                if (decryptedPayload.length == 0 || finalFlag)
                {
                    break;
                }
                currentChunk = currentChunk.add(BigInteger.ONE);
            }
        }
        catch (MessageTypeException | MessageFormatException e)
        {
            throw new SaltpackException("Error processing saltpack message. Message either malformed or not intended for saltpack.", e);
        }
    }
}
