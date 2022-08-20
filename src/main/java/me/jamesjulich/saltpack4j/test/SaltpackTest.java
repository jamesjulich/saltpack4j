package me.jamesjulich.saltpack4j.test;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.utils.Key;
import me.jamesjulich.saltpack4j.SaltPacker;
import me.jamesjulich.saltpack4j.exception.SaltpackException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SaltpackTest
{
    public static void main(String[] args) throws SaltpackException, IOException, SodiumException
    {
        /*
            For testing:
            Sender pub: 5C5C969C00B9E0EBBB8D14E9C8ED5165B78BAD06E8A7B9E7FA0CC6F617FDB967
            Sender private: 089BB77511D40AF4C307DCE4179EB041E6EA645B698C6D7C72D18D73885E1B2B

            Recipient public: 499F056E9F9A11CF18B7CA8326CEC70BB89FBEDEA399535B7B57299B2345FD4F
            Recipient private: 50991DBD243BF51CD46AFFA124A53FB46F4216241E246848E051D458E3AC26A1
        */

        // Create an instance of the SaltPacker class to interact with the saltpack4j API.
        SaltPacker saltpackInstance = new SaltPacker(new LazySodiumJava(new SodiumJava()));

        // Turn Hex string into usable keys.
        byte[] pubKey = Key.fromHexString("499F056E9F9A11CF18B7CA8326CEC70BB89FBEDEA399535B7B57299B2345FD4F").getAsBytes();
        byte[] senderPrivKey = Key.fromHexString("089BB77511D40AF4C307DCE4179EB041E6EA645B698C6D7C72D18D73885E1B2B").getAsBytes();
        byte[] recipPrivateKey = Key.fromHexString("50991DBD243BF51CD46AFFA124A53FB46F4216241E246848E051D458E3AC26A1").getAsBytes();

        // Encrypt a simple "Hello world!" message, send output to 'encryptOut'.
        ByteArrayOutputStream encryptOut = new ByteArrayOutputStream();
        saltpackInstance.getEncryptionHandler().encrypt(
                "Hello world!".getBytes(), // Bytes to encrypt
                new byte[][]{pubKey}, // Array of keys to encrypt message for
                senderPrivKey, // Sender's private key
                2, // Which major version to encrypt for? 1 or 2
                true, // Send anonymously? TODO Allow senderPrivateKey to be null for anonymous message
                true, // Are recipients anonymous or visible to everyone?
                encryptOut // Output stream to send encrypted bytes to.
        );
        byte[] encryptedMessage = encryptOut.toByteArray();

        // Create an armored string (so that the message could be send across a plaintext chat, email, etc)
        String armored = saltpackInstance.getArmorHandler().armor(encryptedMessage, "ENCRYPTED MESSAGE");
        System.out.println("Armored string: \n" + armored + "\n\n");

        // Dearmor the string
        byte[] dearmoredBytes = saltpackInstance.getArmorHandler().dearmor(armored);

        // Decrypt the bytes.
        ByteArrayOutputStream decryptOut = new ByteArrayOutputStream();
        saltpackInstance.getEncryptionHandler().decrypt(
                dearmoredBytes,
                recipPrivateKey,
                decryptOut
        );
        byte[] decryptedBytes = decryptOut.toByteArray();

        // Print decrypted message.
        String decryptedMessage = new String(decryptedBytes);
        System.out.println("Decrypted message: " + decryptedMessage);

        /*
            Now that you've seen how easy the API is to use, go read the spec at https://saltpack.org !

            This project is in heavy development and is not recommended for production use. We would love
            to get to that point, though, and you can make that happen by contributing! Thank you so much!
         */
    }
}
