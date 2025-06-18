import java.nio.file.*;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Arrays;

import javax.crypto.Cipher;

public class CryptoUtils {

    public static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception e) {
            return KeyFactory.getInstance("EC").generatePrivate(spec);
        }

    }

    public static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        
        try {
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            return KeyFactory.getInstance("EC").generatePublic(spec);
        }

    }

    //Firma con chiave privata
    public static byte[] sign(byte[] data, PrivateKey priv) throws Exception {
        String algorithm = getSignatureAlgorithm(priv);
        Signature sig = Signature.getInstance(algorithm);
        sig.initSign(priv);
        sig.update(data);
        return sig.sign();
    }

    // Verifica firma
    public static boolean verify(byte[] data, byte[] signature, PublicKey pub) throws Exception {
        String algorithm = getSignatureAlgorithm(pub);
        Signature sig = Signature.getInstance(algorithm);
        sig.initVerify(pub);
        sig.update(data);
        return sig.verify(signature);
    }


    // Cifra un messaggio con la chiave pubblica RSA
    public static byte[] encryptRSA(byte[] plaintext, PublicKey publicKey) throws Exception {
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("Chiave non RSA");
        }
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext);
    }

    // Decifra un messaggio con la chiave privata RSA
    public static byte[] decryptRSA(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new IllegalArgumentException("Chiave non RSA");
        }
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(ciphertext);
    }

    private static String getSignatureAlgorithm(Key key) {
            if (key instanceof RSAPrivateKey || key instanceof RSAPublicKey)
                return "SHA256withRSA";
            if (key instanceof ECPrivateKey || key instanceof ECPublicKey)
                return "SHA256withECDSA";
            throw new IllegalArgumentException("Unsupported key type: " + key.getAlgorithm());
        }

}

