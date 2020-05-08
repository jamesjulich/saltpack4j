import com.goterl.lazycode.lazysodium.LazySodium;

public class SaltPacker
{
    private LazySodium sodiumInstance;

    public SaltPacker(LazySodium sodiumInstance)
    {
        this.sodiumInstance = sodiumInstance;
    }


}
