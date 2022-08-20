import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.utils.Key;
import me.jamesjulich.saltpack4j.SaltPacker;
import me.jamesjulich.saltpack4j.exception.SaltpackException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

public class SaltpackTest
{
  /**
   * This method checks that the API can encrypt and decrypt a random String and get the same
   * output as the original input.
   */
  @Test
  public void testEncryptDecrypt() throws SodiumException, SaltpackException, IOException
  {
    char[] charAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()\"';:.,<>?/[]|`~+=".toCharArray();

    int randStringLength = (int) ((Math.random() * (30 - 1)) + 1);
    StringBuilder randStringBuilder = new StringBuilder();
    for (int i = 0; i < randStringLength; i++)
    {
      randStringBuilder.append(charAlphabet[(int) ((Math.random() * (charAlphabet.length)))]);
    }

    String randString = randStringBuilder.toString();

    // These are the same keys used in SaltpackExample.java

    // Turn Hex string into usable keys.
    byte[] senderPrivKey = Key.fromHexString("089BB77511D40AF4C307DCE4179EB041E6EA645B698C6D7C72D18D73885E1B2B").getAsBytes();
    byte[] recipPublicKey = Key.fromHexString("499F056E9F9A11CF18B7CA8326CEC70BB89FBEDEA399535B7B57299B2345FD4F").getAsBytes();
    byte[] recipPrivateKey = Key.fromHexString("50991DBD243BF51CD46AFFA124A53FB46F4216241E246848E051D458E3AC26A1").getAsBytes();

    SaltPacker sp = new SaltPacker(new LazySodiumJava(new SodiumJava()));
    ByteArrayOutputStream encryptOut = new ByteArrayOutputStream();

    sp.getEncryptionHandler().encrypt(
        randString.getBytes(),
        new byte[][]{recipPublicKey},
        recipPrivateKey,
        2,
        true,
        true,
        encryptOut
    );

    byte[] encryptedBytes = encryptOut.toByteArray();

    ByteArrayOutputStream decryptOut = new ByteArrayOutputStream();
    sp.getEncryptionHandler().decrypt(
        encryptedBytes,
        recipPrivateKey,
        decryptOut);

    String resultString = decryptOut.toString();
    assertEquals(randString, resultString);
  }

  /**
   * This method tests that the API can armor bytes into a String and dearmor them back to bytes.
   * Generates a random byte array to armor.
   */
  @Test
  public void testArmorDearmor() throws SaltpackException
  {
    Random rand = new Random();

    byte[] randBytes = new byte[rand.nextInt(100 - 1) + 1];
    rand.nextBytes(randBytes);

    SaltPacker sp = new SaltPacker(new LazySodiumJava(new SodiumJava()));
    String armored = sp.getArmorHandler().armor(randBytes,
        "ENCRYPTED MESSAGE");

    assertArrayEquals(
        randBytes,
        sp.getArmorHandler().dearmor(armored));
  }
}
