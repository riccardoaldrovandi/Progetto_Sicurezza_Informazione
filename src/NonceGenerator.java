//Questa classe è necessaria per garantire che un nonce non si ripresenti due volte nella stessa comunicazione
//se così succedesse l'intera cifratura simmetrica chacha20-poly1503 sarebbe compromessa
//per mitigare ciò il nonce è diviso in due parti il vero e propio numero random e un contatore
//per evitare che due numeri uguali si ripetino
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class NonceGenerator {
    private final byte[] baseNonce; // 4 bytes
    private long counter;           // 8 bytes

    public NonceGenerator() {
        this.baseNonce = new byte[4];
        SecureRandom random = new SecureRandom();
        random.nextBytes(baseNonce);
        this.counter = 0;
    }

    public synchronized byte[] nextNonce() {
        byte[] nonce = new byte[12]; // 96-bit nonce
        System.arraycopy(baseNonce, 0, nonce, 0, 4); // 4-byte prefix
        byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter++).array();
        System.arraycopy(counterBytes, 0, nonce, 4, 8); // 8-byte counter
        return nonce;
    }
}