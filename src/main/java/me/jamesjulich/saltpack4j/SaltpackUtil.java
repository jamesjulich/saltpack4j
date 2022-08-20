package me.jamesjulich.saltpack4j;

import com.goterl.lazysodium.LazySodium;
import com.goterl.lazysodium.utils.Key;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

public class SaltpackUtil
{
    LazySodium sodiumInstance;

    SaltpackUtil(LazySodium sodiumInstance)
    {
        this.sodiumInstance = sodiumInstance;
    }

    /**
     * "Chunks" an array of elements into an ArrayList of smaller arrays.
     * @param toChunk the large array to "chunk"
     * @param chunkSize the size of the smaller chunks
     * @return an ArrayList containing the smaller chunks
     * @param <T> the type of array to chunk
     */
    public static <T> ArrayList<T[]> chunkArray(T[] toChunk, int chunkSize)
    {
        ArrayList<T[]> chunks = new ArrayList<>();
        for (int i = 0; i < toChunk.length; i += chunkSize)
        {
            chunks.add(Arrays.copyOfRange(toChunk, i, Math.min(i + chunkSize, toChunk.length)));
        }
        return chunks;
    }

    /**
     * Generate a keypair.
     * @return an array containing a public and private key {pub, priv}
     */
    public Key[] generateKeypair()
    {
        // TODO Clean up and make sure this is the most secure method of generating NaCl keys.
        SecureRandom sr = new SecureRandom();
        byte[] privBytes = new byte[32];
        sr.nextBytes(privBytes);

        Key pubKey = sodiumInstance.cryptoScalarMultBase(Key.fromBytes(privBytes));
        Key privKey = Key.fromBytes(privBytes);
        return new Key[]{pubKey, privKey};
    }
}
