import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;


public class Server {
    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(5000);
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        while(true) {

        System.out.println("[Server] In ascolto sulla porta 5000...");
        Socket socket = serverSocket.accept();

        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
		SecureRandom random = new SecureRandom();
		byte[] serverNonce = new byte[32];
		random.nextBytes(serverNonce);

		out.write(serverNonce);

		int id = in.readInt();
		PrivateKey serverPrivateKey = null;
		PublicKey clientPublicKey = null;
		/*try{
		serverPrivateKey = CryptoUtils.loadPrivateKey("server_private_key.der");
        clientPublicKey = CryptoUtils.loadPublicKey(id+"_public_key.der");
		// 1. Genera chiave DH
		}
		catch(Exception e){
			System.out.println("Certificato di ID "+id+" non trovato, connessione chiusa con socket...");
			socket.close();
			continue;
		}*/
		
		try {
			serverPrivateKey = CryptoUtils.loadPrivateKey("../keys/server_private_key.der");
		} catch (Exception e) {
			System.out.println("[Server] Errore caricamento chiave privata del server.");
			e.printStackTrace();
			socket.close();
			continue;
		}
		
		try {
			clientPublicKey = CryptoUtils.loadPublicKey("../keys/" + id + "_public_key.der");
		} catch (Exception e) {
			System.out.println("[Server] Errore caricamento chiave pubblica del client ID " + id);
			e.printStackTrace();
			socket.close();
			continue;
		}
		

		//Genera chiave ECDH
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair keyPair = kpg.generateKeyPair();

		// Invia chiave pubblica ECDH cifrata + firmata
		byte[] ecPubEncoded = keyPair.getPublic().getEncoded();
		byte[] encryptedPub = CryptoUtils.encryptRSA(ecPubEncoded, clientPublicKey);
		byte[] signature = CryptoUtils.sign(sha256.digest(encryptedPub), serverPrivateKey);

		out.writeInt(encryptedPub.length);
		out.write(encryptedPub);
		out.writeInt(signature.length);
		out.write(signature);

		// Ricezione chiave pubblica ECDH del client cifrata + firmata
		int len = in.readInt();
		byte[] clientEnc = new byte[len];
		in.readFully(clientEnc);

		int sigLen = in.readInt();
		byte[] clientSig = new byte[sigLen];
		in.readFully(clientSig);

		if(!CryptoUtils.verify(sha256.digest(clientEnc), clientSig,clientPublicKey)){
			System.out.println("Firma client non corretta, chiusura connessione..");
			socket.close();
			continue;
		}
		byte[] decodedPub = CryptoUtils.decryptRSA(clientEnc, serverPrivateKey);
		KeyFactory kf = KeyFactory.getInstance("EC");
		X509EncodedKeySpec x509 = new X509EncodedKeySpec(decodedPub);
		PublicKey clientECPub = kf.generatePublic(x509);

		// Calcolo chiave condivisa
		KeyAgreement ka = KeyAgreement.getInstance("ECDH");
		ka.init(keyPair.getPrivate());
		ka.doPhase(clientECPub, true);
		byte[] sharedSecret = ka.generateSecret();

		// Derivazione chiave simmetrica con SHA-256 (ChaCha20 richiede 32 byte)
		sha256 = MessageDigest.getInstance("SHA-256");
		sha256.update(sharedSecret);
		sha256.update(serverNonce); //il nonce è usato per evitare replay attack nello scambio dh
		byte[] chachaKey = sha256.digest();

		SecretKey key = new SecretKeySpec(chachaKey, "ChaCha20");

		NonceGenerator nonceG = new NonceGenerator();
		Set<String> usedNonces = new HashSet<>();
        //System.out.println("Chiave Asimmetrica generataa "+Translator.toHex(chachaKey));
        while(true) {
			String plaintext = null;
	        try {
		        plaintext = decryptMessage(in,key,usedNonces);
		        System.out.println("[Server] Messaggio decifrato ricevuto: " + new String(plaintext));
		        sendEncryptedMessage(out,key,"ACK",nonceG);
	        } catch (ReplayAttackException r){
				System.out.println("Replay attack rilevato, chiusura connesione");
			}
			catch (EOFException e) {
	            System.out.println("[Server] Il client ha chiuso la connessione.");
	            break;
	        } catch (AEADBadTagException e) {
	            System.out.println("[Server] Messaggio compromesso!");
	            sendEncryptedMessage(out, key, "COMPROMISED",nonceG);
	        } catch (IOException e) {
	            System.out.println("[Server] Errore di I/O: " + e.getMessage());
	            break;
	        }
        }
        socket.close();
        }
    }

	private static void sendEncryptedMessage(DataOutputStream out, SecretKey key, String message, NonceGenerator ng) throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	DataOutputStream dos = new DataOutputStream(baos);//usati per unire la lunghezza del messaggio e il messaggio nel cifrato
    	//in questo modo l'attaccante non vede in chiaro quanto è lungo il messaggio cifrato
    	dos.writeInt(message.getBytes().length);  // lunghezza del messaggio
    	dos.write(message.getBytes());            // messaggio vero e proprio
    	byte[] plainMessage = baos.toByteArray();
    	byte[] nonce = ng.nextNonce();
	    new SecureRandom().nextBytes(nonce);
	    Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305", "SunJCE");
	    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
	    byte[] ciphertext = cipher.doFinal(plainMessage);
	   
	    out.write(nonce);
	    out.writeInt(ciphertext.length);
	    out.write(ciphertext);
	}
	
	private static String decryptMessage(DataInputStream in, SecretKey key,Set<String> usedNonces) throws Exception,ReplayAttackException{
    	byte[] nonce = new byte[12];
    	in.readFully(nonce);
		String nonceHex = Base64.getEncoder().encodeToString(nonce);
        if (usedNonces.contains(nonceHex)) {
            throw new ReplayAttackException();
        }
        usedNonces.add(nonceHex);
    	int ctLen = in.readInt();
    	byte[] ciphertext = new byte[ctLen];
    	in.readFully(ciphertext);
    	
    	//Decifrazione
    	Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305", "SunJCE");
    	cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
    	byte[] plaintext = cipher.doFinal(ciphertext);

    	// Estrazione lunghezza e messaggio originale
    	ByteArrayInputStream bais = new ByteArrayInputStream(plaintext);
    	DataInputStream dis = new DataInputStream(bais);
    	int msgLen = dis.readInt();
    	byte[] messageBytes = new byte[msgLen];
    	dis.readFully(messageBytes);
    	return new String(messageBytes);

    }
}
