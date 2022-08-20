package me.jamesjulich.saltpack4j;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.utils.Key;
import me.jamesjulich.saltpack4j.example.SaltpackExample;
import me.jamesjulich.saltpack4j.exception.SaltpackException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Scanner;

public class Main
{
    public static final String VERSION_STRING = "1.0-SNAPSHOT";
    public static final String ENCRYPT_USAGE = "encrypt <recipient public key hex> <sender private key hex>";
    public static final String DECRYPT_USAGE = "decrypt <sender private key hex>";

    public static final String HELP_STRING =
            "\n--------------------------" + "\n" +
            "saltpack4j v" + VERSION_STRING +
            "\n--------------------------\n" +
            ENCRYPT_USAGE + "\n" +
            DECRYPT_USAGE + "\n" +
            "example - runs the example code provided in the saltpack source code\n" +
            "help - commands list\n" +
            "The encrypt function will output an armored String, the decrypt function will accept an armored String as input.";

    public static void main(String[] args)
    {
        try
        {
            Scanner inputScanner = new Scanner(System.in);

            System.out.println("saltpack4j v" + VERSION_STRING);
            System.out.print("Type a command or 'help' for options: ");

            String command = inputScanner.nextLine();
            String[] commandParts = command.trim().split(" ");

            SaltPacker saltpackInstance;

            if (commandParts[0].equalsIgnoreCase("help"))
            {
                System.out.println(HELP_STRING);
            }
            else if (commandParts[0].equalsIgnoreCase("example"))
            {
                SaltpackExample.main(new String[0]);
            }
            else if (commandParts[0].equalsIgnoreCase("encrypt"))
            {
                if (commandParts.length < 3)
                {
                    argumentError(ENCRYPT_USAGE);
                    return;
                }
                saltpackInstance = new SaltPacker(new LazySodiumJava(new SodiumJava()));

                byte[] pubKey = Key.fromHexString(commandParts[1]).getAsBytes();
                byte[] senderPrivKey = Key.fromHexString(commandParts[2]).getAsBytes();

                System.out.print("What message to encrypt? (press enter then ctrl+d or ctrl+z to end): ");

                String toEncrypt = "";
                while (inputScanner.hasNextLine())
                {
                    toEncrypt += inputScanner.nextLine();
                }

                // Encrypt input and send output to 'encryptOut'
                ByteArrayOutputStream encryptOut = new ByteArrayOutputStream();
                saltpackInstance.getEncryptionHandler().encrypt(
                        toEncrypt.getBytes(), // Bytes to encrypt
                        new byte[][]{pubKey}, // Array of keys to encrypt message for
                        senderPrivKey, // Sender's private key
                        2, // Which major version to encrypt for? 1 or 2
                        true, // Send anonymously? TODO Allow senderPrivateKey to be null for anonymous message
                        true, // Are recipients anonymous or visible to everyone?
                        encryptOut // Output stream to send encrypted bytes to.
                );
                byte[] encryptedMessage = encryptOut.toByteArray();

                // Create an armored string (so that the message could be sent across a plaintext chat, email, etc)
                String armored = saltpackInstance.getArmorHandler().armor(encryptedMessage, "ENCRYPTED MESSAGE");
                System.out.println("Output armored string: \n" + armored + "\n\n");
            }
            else if (commandParts[0].equalsIgnoreCase("decrypt"))
            {
                saltpackInstance = new SaltPacker(new LazySodiumJava(new SodiumJava()));
                if (commandParts.length < 2)
                {
                    argumentError(ENCRYPT_USAGE);
                    return;
                }

                byte[] recipPrivateKey = Key.fromHexString(commandParts[1]).getAsBytes();
                System.out.print("Armored message to decrypt? (press enter then ctrl+d or ctrl+z to end): ");
                String armored = "";
                while (inputScanner.hasNextLine())
                {
                    armored += inputScanner.nextLine();
                }
                inputScanner.close();

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
            }
            else
            {
                System.out.println("Invalid command. Type 'help' for a list of valid commands.");
            }
        }
        catch (SodiumException | SaltpackException | IOException e)
        {
            System.out.println("Error processing request. Check arguments. Are keys formatted correctly?");
        }
    }

    public static void argumentError(String usage)
    {
        System.out.println("Incorrect arguments. Usage: " + usage);
    }
}
