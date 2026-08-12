package wk;

import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/** Danubetech looks for tink or libsodium on the classpath; neither is here, so back it with BouncyCastle. */
final class Ed25519Bc extends Ed25519Provider {

    static void install() { Ed25519Provider.set(new Ed25519Bc()); }

    @Override
    public void generateEC25519KeyPair(byte[] publicKey, byte[] privateKey) {
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        generateEC25519KeyPairFromSeed(publicKey, privateKey, seed);
    }

    @Override
    public void generateEC25519KeyPairFromSeed(byte[] publicKey, byte[] privateKey, byte[] seed) {
        byte[] pub = new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
        System.arraycopy(pub, 0, publicKey, 0, 32);
        System.arraycopy(seed, 0, privateKey, 0, 32);   // libsodium layout: seed || public
        System.arraycopy(pub, 0, privateKey, 32, 32);
    }

    @Override
    public byte[] sign(byte[] content, byte[] privateKey) {
        Ed25519Signer s = new Ed25519Signer();
        s.init(true, new Ed25519PrivateKeyParameters(Arrays.copyOfRange(privateKey, 0, 32), 0));
        s.update(content, 0, content.length);
        return s.generateSignature();
    }

    @Override
    public boolean verify(byte[] content, byte[] signature, byte[] publicKey) {
        Ed25519Signer s = new Ed25519Signer();
        s.init(false, new Ed25519PublicKeyParameters(publicKey, 0));
        s.update(content, 0, content.length);
        return s.verifySignature(signature);
    }
}
