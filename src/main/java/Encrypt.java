import com.goterl.lazycode.lazysodium.LazySodium;
import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.interfaces.Box;
import com.goterl.lazycode.lazysodium.interfaces.SecretBox;
import com.goterl.lazycode.lazysodium.utils.Key;
import com.goterl.lazycode.lazysodium.utils.KeyPair;
import exception.SaltpackException;
import org.apache.commons.lang3.ArrayUtils;
import org.msgpack.core.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

public class Encrypt
{
    final static int MAJOR_VERSION = 2;
    final static int MINOR_VERSION = 1;
    final static int MODE = 0;

    final static String SENDER_KEY_SBOX_NONCE = "saltpack_sender_key_sbox";
    final static String PAYLOAD_KEY_BOX_NONCE_V1 = "saltpack_payload_key_box";
    final static String PAYLOAD_KEY_BOX_NONCE_V2 = "saltpack_recipsb";

    final static String myPubKey = "0121e188d25594c9315e78065ab9331bbc3590de83c5ae9d93e445754547b86905720a";

    private static LazySodium sodiumInstance;

    public Encrypt(LazySodium sodiumInstance)
    {
        this.sodiumInstance = sodiumInstance;
    }

    public static byte[] getPayloadKeyBoxNonce(int majorVersion, long recipIndex)
    {
        if (majorVersion == 1)
            return PAYLOAD_KEY_BOX_NONCE_V1.getBytes();
        else
            return ArrayUtils.addAll(PAYLOAD_KEY_BOX_NONCE_V2.getBytes(), Armor.bigIntToByteArrayUnsigned(BigInteger.valueOf(recipIndex), 8));
    }

    //Mode 0 = encryption, mode 1 = decryption.
    public static byte[] generateMACKey(byte[] key1, byte[] key2, byte[] key3, byte[] headerHash, long recipientIndex, int majorVersion, int mode) throws SaltpackException, SodiumException
    {
        if (mode != 0 && mode != 1)
        {
            throw new SaltpackException("Invalid MAC key generation mode.");
        }

        if (majorVersion == 1)
        {
            throw new SaltpackException("Invalid/unsupported major version ' " + majorVersion + "'.");
        }
        else if (majorVersion == 2)
        {
            /*
                This is slightly confusing, but it prevents repeating a LOT of code.

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
            System.arraycopy(headerHash, 0, headerHashFirstBytes, 0, 16);

            byte[] indexBytes = Armor.bigIntToByteArrayUnsigned(BigInteger.valueOf(recipientIndex), 8);

            byte[] nonceBase = ArrayUtils.addAll(headerHashFirstBytes, indexBytes);
            nonceBase[15] &= 0xfe; //Clear the least significant bit at index 15.

            byte[] macKeyBoxLongTermKey = new byte[Box.MACBYTES + 32];
            sodiumInstance.cryptoBoxEasy(macKeyBoxLongTermKey, new byte[32], 32, nonceBase, key1, key2);

            nonceBase[15] |= 0x01; //Set least significant bit of byte at index 15.

            byte[] macKeyBoxEphemeralKey = new byte[Box.MACBYTES + 32];
            sodiumInstance.cryptoBoxEasy(macKeyBoxEphemeralKey, new byte[32], 32, nonceBase,
                    (mode == 0 ) ? key1 : key3,
                    (mode == 0) ? key3 : key2);

            byte[] concat = new byte[64];
            System.arraycopy(macKeyBoxLongTermKey, macKeyBoxLongTermKey.length - 32, concat, 0, 32);
            System.arraycopy(macKeyBoxEphemeralKey, macKeyBoxEphemeralKey.length - 32, concat, 32, 32);

            byte[] macKey = new byte[64];
            sodiumInstance.cryptoHashSha512(macKey, concat, 64);

            return macKey;
        }
        else
        {
            throw new SaltpackException("Invalid/unsupported major version ' " + majorVersion + "'.");
        }
    }

    public static void encrypt() throws IOException, SodiumException
    {
        byte[] payloadKey = sodiumInstance.randomBytesBuf(32); //1. Generate a random 32 byte (256 bit) symmetric encryption key.
        KeyPair ephemeralKey = sodiumInstance.cryptoBoxKeypair(); //2. Generate a random keypair to be used for this message only.

        String senderSbox = sodiumInstance.cryptoSecretBoxEasy(ephemeralKey.getPublicKey().getAsHexString(), SENDER_KEY_SBOX_NONCE.getBytes(), Key.fromBytes(payloadKey));
        //String recipEncryptedPayloadKey = sodiumInstance.cryptoBoxEasy(Key.fromBytes(payloadKey).getAsHexString(), (PAYLOAD_KEY_BOX_NONCE + "0").getBytes(), new KeyPair(Key.fromHexString(myPubKey), ephemeralKey.getSecretKey()));

        //Create MessagePack header packet
        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        packer.packArrayHeader(6); //The header array contains 6 objects.

        //Format
        packer.packString("saltpack");

        //Version
        packer.packArrayHeader(2); //The version object is a list of two integers, ex. [2, 0].
        packer.packInt(MAJOR_VERSION);
        packer.packInt(MINOR_VERSION);

        //Mode
        packer.packInt(MODE);

        //Ephemeral public key
        packer.packString(ephemeralKey.getPublicKey().getAsHexString());

        //Sender secretbox
        packer.packString(senderSbox);

        //Recipients list
        int recipsNum = 1;
        packer.packArrayHeader(recipsNum);
        packer.packString(myPubKey);
        //packer.packString(recipEncryptedPayloadKey);

        byte[] packedByteArr = packer.toByteArray();

        //Hash the header
        byte[] hashBytes = new byte[64];
        sodiumInstance.cryptoHashSha512(hashBytes, packedByteArr, packedByteArr.length);
        String hashString = sodiumInstance.toHexStr(hashBytes);

        //Encode the header packet a second time, this time into a bin object.
        MessageBufferPacker bytePacker = MessagePack.newDefaultBufferPacker();
        bytePacker.packBinaryHeader(packedByteArr.length);
        bytePacker.addPayload(packedByteArr);

        //Find a MAC key for my public key.
        byte[] newArray = Arrays.copyOfRange(hashBytes, 0, 16);
    }

    public static void decrypt() throws IOException, SaltpackException
    {
        try
        {
            Armor a = new Armor();

            //Sender pub: 5C5C969C00B9E0EBBB8D14E9C8ED5165B78BAD06E8A7B9E7FA0CC6F617FDB967
            //Sender private: 089BB77511D40AF4C307DCE4179EB041E6EA645B698C6D7C72D18D73885E1B2B

            //Recip pub: 499F056E9F9A11CF18B7CA8326CEC70BB89FBEDEA399535B7B57299B2345FD4F
            //Recip priv: 50991DBD243BF51CD46AFFA124A53FB46F4216241E246848E051D458E3AC26A1

            byte[] privKey = Key.fromHexString("50991DBD243BF51CD46AFFA124A53FB46F4216241E246848E051D458E3AC26A1").getAsBytes();

            byte[] bytes = a.dearmor("BEGIN SALTPACK ENCRYPTED MESSAGE. kcJn5brvybfNjz6 D5litY0cgiExVuZ xnTvXbHueR5w5Ri 6G0Pm7Z4TgNVvDG fZJpMFbqqcutcid v87UC8zdZ1vS0Lp kRYbz0QhoodTzMy 0BZJx27bzOPFZv6 QI51rrRsNbnhSBQ UmkSc1v0V4TUYDf PPPLFjgblox5MjP Sqb3oayvcYhKVYd 2CqgpxQUbJbEmW6 zBTK6cPAHVhIZIK mENgutiU4HsUJx8 s5QW3EFQyGwXoW8 qgTRqsEDAjLdeCj MsXI3G58qKNmrt8 RvJEqjGFvYe6yEC BA8AEpSt18kdjWy ChZGzYFQz5oRZZv 1PmmdaZv1GgBZtH Tl6jJ7veLkU3vD3 iMchAgXHB4UuF. END SALTPACK ENCRYPTED MESSAGE.");
            MessageUnpacker messageUnpacker = MessagePack.newDefaultUnpacker(bytes); //missed opportunity for an unpack saltpack joke?

            byte[] encodedHeader = new byte[messageUnpacker.unpackBinaryHeader()];
            messageUnpacker.readPayload(encodedHeader);

            byte[] headerHash = new byte[64]; //SHA-512 hash = 512 bits = 64 bytes.
            sodiumInstance.cryptoHashSha512(headerHash, encodedHeader, encodedHeader.length);
            System.out.println("Header hash: " + sodiumInstance.toHexStr(headerHash));

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

            headerUnpacker.unpackArrayHeader(); //Version array

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

            //String sharedSecret = sodiumInstance.cryptoBoxBeforeNm(ephemeralPubKey, privKey);
            byte[] sharedSecret = new byte[48];
            sodiumInstance.cryptoBoxBeforeNm(sharedSecret, ephemeralPubKey, privKey);

            byte[] senderSbox = new byte[headerUnpacker.unpackBinaryHeader()];
            headerUnpacker.readPayload(senderSbox);

            int recipientsNum = headerUnpacker.unpackArrayHeader();
            System.out.println("Reciplist length: " + recipientsNum);

            int currentRecipNumber = 0;
            byte[] payloadKey = null;
            while (currentRecipNumber < recipientsNum)
            {
                int recipEntryLength = headerUnpacker.unpackArrayHeader();
                if (headerUnpacker.getNextFormat() == MessageFormat.NIL) //If recipients are anonymous
                {
                    headerUnpacker.unpackNil();
                }
                else
                {
                    headerUnpacker.readPayload(headerUnpacker.unpackBinaryHeader());//TODO Add known recipients to saltpack message class.
                }

                byte[] payloadKeyBox = new byte[headerUnpacker.unpackBinaryHeader()];
                headerUnpacker.readPayload(payloadKeyBox);

                payloadKey = new byte[32];

                if (!sodiumInstance.cryptoBoxOpenEasyAfterNm(payloadKey, payloadKeyBox, payloadKeyBox.length, getPayloadKeyBoxNonce(majorVersion, currentRecipNumber), sharedSecret))
                {
                    System.out.println("that aint it chief, recip #" + currentRecipNumber);
                    currentRecipNumber++;
                    continue;
                }
                break; //If there is no error, break from the loop to signify that a match was found.
            }

            //If we aren't able to access the payload key box.
            if (currentRecipNumber >= recipientsNum)
            {
                throw new SaltpackException("Private key could not decrypt message. Are you using the wrong key?");
            }

            byte[] senderKey = new byte[32];
            sodiumInstance.cryptoSecretBoxOpenEasy(senderKey, senderSbox, senderSbox.length, SENDER_KEY_SBOX_NONCE.getBytes(), payloadKey);
        }
        catch (MessageTypeException | MessageFormatException e)
        {
            throw new SaltpackException("Error processing saltpack message. Message either malformed or not intended for saltpack.", e);
        }
    }

    public static void main(String[] args)
    {
        try
        {
            sodiumInstance = new LazySodiumJava(new SodiumJava());

            Armor a = new Armor();

            decrypt();


            /*
            SecureRandom sr = new SecureRandom();
            byte[] privBytes = new byte[32];
            sr.nextBytes(privBytes);

            byte[] pubKey = sodiumInstance.cryptoScalarMultBase(Key.fromBytes(privBytes)).getAsBytes();

            System.out.println("length: " + privBytes.length + " " + pubKey.length);

            System.out.println(sodiumInstance.toHexStr(privBytes));
            System.out.println(sodiumInstance.toHexStr(pubKey));



            System.out.println("length: " + Key.fromHexString("499F056E9F9A11CF18B7CA8326CEC70BB89FBEDEA399535B7B57299B2345FD4F").getAsBytes().length + " " + Key.fromHexString("50991DBD243BF51CD46AFFA124A53FB46F4216241E246848E051D458E3AC26A1").getAsBytes().length);
             */
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}