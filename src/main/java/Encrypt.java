import com.goterl.lazycode.lazysodium.LazySodium;
import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.interfaces.Hash;
import com.goterl.lazycode.lazysodium.utils.Key;
import com.goterl.lazycode.lazysodium.utils.KeyPair;
import org.apache.commons.lang3.ArrayUtils;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePacker;
import org.msgpack.core.MessageUnpacker;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class Encrypt
{
    final static int MAJOR_VERSION = 2;
    final static int MINOR_VERSION = 1;
    final static int MODE = 0;

    final static String senderPubKeySBoxNonce = "saltpack_sender_key_sbox";
    final static String recipientPayloadBoxNonce = "saltpack_recipsb_";

    final static String myPubKey = "0121e188d25594c9315e78065ab9331bbc3590de83c5ae9d93e445754547b86905720a";

    private static LazySodium sodiumInstance;

    public Encrypt(LazySodium sodiumInstance)
    {
        this.sodiumInstance = sodiumInstance;
    }

    public static void encrypt() throws IOException, SodiumException
    {
        byte[] payloadKey = sodiumInstance.randomBytesBuf(32); //1. Generate a random 32 byte (256 bit) symmetric encryption key.
        KeyPair ephemeralKey = sodiumInstance.cryptoBoxKeypair(); //2. Generate a random keypair to be used for this message only.

        String senderSbox = sodiumInstance.cryptoSecretBoxEasy(ephemeralKey.getPublicKey().getAsHexString(), senderPubKeySBoxNonce.getBytes(), Key.fromBytes(payloadKey));
        String recipEncryptedPayloadKey = sodiumInstance.cryptoBoxEasy(Key.fromBytes(payloadKey).getAsHexString(), (recipientPayloadBoxNonce + "0").getBytes(), new KeyPair(Key.fromHexString(myPubKey), ephemeralKey.getSecretKey()));

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
        packer.packString(recipEncryptedPayloadKey);

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

    public static void main(String[] args) throws IOException
    {
        sodiumInstance = new LazySodiumJava(new SodiumJava());

        Armor a = new Armor();

        /*
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        MessagePacker packer = MessagePack.newDefaultPacker(out);
        packer.packArrayHeader(1);
        packer.packInt(-1);
        packer.flush();


        System.out.println(a.encodeBlock(ArrayUtils.toObject(out.toByteArray())));
        byte[] bytes = a.decodeBlock(ArrayUtils.toObject(a.encodeBlock(ArrayUtils.toObject(out.toByteArray())).toCharArray()));
        MessageUnpacker up = MessagePack.newDefaultUnpacker(bytes);


        byte[] encoded = new byte[up.unpackBinaryHeader()];
        up.readPayload(encoded);

        MessageUnpacker second = MessagePack.newDefaultUnpacker(encoded);

        //System.out.println(up.unpackArrayHeader());
        System.out.println(second.unpackArrayHeader());
        System.out.println(second.unpackInt());
        */



        byte[] bytes = a.dearmor("BEGIN KEYBASE SALTPACK ENCRYPTED MESSAGE. kiNJamlTJ29ZvW4 RHAOg9hm6h1Di8A zHj2idMNBNkEhX0 YP1YrAZS3r2cyGj U6HR7297tl9nx8b IwVvk4XhHpRgMtq CryiF3QfOIouUsu M5gED7JRKNFSxfa 0J4cUT42hgn0Xl3 MQHqb7QgDsiRWTZ 7gkdFqjvWF4HOtg 34OiJ9P9hqPl6r8 OFF0MSfw6EoyC9S NHf4QSiFn8WxCQt c7tHcmTtaAWH7Dt ZUoHHY1tFapauKx wo3mSJABX0CCWlY tm126fzjMXXWBlv CgoMigoBric9N3R S0iVFEwVlnMos9J 2BkyOL4ZEFN4NTo 0oBfNvNvkGQS3AM bQLW0KX8KIjzKMy 7Yr3x9CbzeqDGbP Yqx0ook9rCvmJzN 74l75GHl75tpNMW L0NhygsFkVz61E3 UUgrmetDY1GBHue mmeiyzx68fL5NpY hstjoN13zOeoPik nBhXplsX49yCP8e BmCVbIFO1FEM5JT 4609C4Z. END KEYBASE SALTPACK ENCRYPTED MESSAGE.");
        MessageUnpacker up = MessagePack.newDefaultUnpacker(bytes);
        byte[] encoded = new byte[up.unpackBinaryHeader()];
        up.readPayload(encoded);
        MessageUnpacker binUnpacker = MessagePack.newDefaultUnpacker(encoded);
        System.out.println(binUnpacker.unpackArrayHeader());
        System.out.println(binUnpacker.unpackString());


        //WORKING!!!
        //System.out.println(new String(a.decodeBlock(ArrayUtils.toObject(a.encodeBlock(ArrayUtils.toObject("1234".getBytes())).toCharArray()))));

        //encrypt();
    }
}
