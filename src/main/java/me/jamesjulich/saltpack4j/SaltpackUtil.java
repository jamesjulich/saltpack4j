package me.jamesjulich.saltpack4j;

import com.goterl.lazycode.lazysodium.LazySodium;
import com.goterl.lazycode.lazysodium.utils.Key;

import java.security.SecureRandom;

public class SaltpackUtil
{
    LazySodium sodiumInstance;

    SaltpackUtil(LazySodium sodiumInstance)
    {
        this.sodiumInstance = sodiumInstance;
    }

    //Returns an 2 element array of Keys. {pub, priv}.
    public Key[] generateKeypair()
    {
        //TODO Clean up and make sure this is the most secure method of generating NaCl keys.
        SecureRandom sr = new SecureRandom();
        byte[] privBytes = new byte[32];
        sr.nextBytes(privBytes);

        Key pubKey = sodiumInstance.cryptoScalarMultBase(Key.fromBytes(privBytes));
        Key privKey = Key.fromBytes(privBytes);
        return new Key[]{pubKey, privKey};
    }
}
