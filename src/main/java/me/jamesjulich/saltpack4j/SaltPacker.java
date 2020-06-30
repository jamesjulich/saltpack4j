package me.jamesjulich.saltpack4j;

import com.goterl.lazycode.lazysodium.LazySodium;

public class SaltPacker
{
    private LazySodium sodiumInstance;
    private Encrypt encryption;
    private Armor armor;
    private SaltpackUtil utilities;

    public SaltPacker(LazySodium sodiumInstance)
    {
        this.sodiumInstance = sodiumInstance;
        this.encryption = new Encrypt(sodiumInstance);
        this.armor = new Armor();
        this.utilities = new SaltpackUtil(sodiumInstance);
    }

    public Encrypt getEncryptionHandler()
    {
        return encryption;
    }

    public Armor getArmorHandler()
    {
        return armor;
    }

    public SaltpackUtil getUtilities()
    {
        return utilities;
    }
}
