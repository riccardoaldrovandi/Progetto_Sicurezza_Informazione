import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;


public class Client {
    public static void main(String[] args) throws Exception {
        if(args.length != 1){
            System.out.println("Param [ID] certificato pub key");
            System.exit(0);
        }
        int id=0;
        try{
            id = Integer.parseInt(args[0].trim());
        }
        catch(Exception e){
            System.out.println("Param [ID] deve essere un numero intero");
            System.exit(0);
        }

        Socket socket = new Socket("localhost", 5000);
        System.out.println("[Client] Connesso al server.");
        Scanner scanner = new Scanner(System.in);
        
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        out.writeInt(id);
        PublicKey serverPublicKey = null;
		PrivateKey clientPrivateKey = null;
        
        try{
            clientPrivateKey = CryptoUtils.loadPrivateKey("../keys/" + id+"_private_key.der");
            serverPublicKey = CryptoUtils.loadPublicKey("../keys/server_public_key.der");
		// 1. Genera chiave DH
		}
		catch(Exception e){
			socket.close();
            System.out.println("Certificati non trovati in locale");
            System.out.println("Private Key Algorithm: " + clientPrivateKey.getAlgorithm());
            System.out.println("Format: " + clientPrivateKey.getFormat());
            System.out.println("Public Key Algorithm: " + serverPublicKey.getAlgorithm());
            System.out.println("Format: " + serverPublicKey.getFormat());
            System.out.println(e.getMessage());
            System.out.print(e.toString());
            System.exit(0);
		}

        // Ricezione chiave pubblica del server
        byte[] serverNonce = new byte[32];
        in.readFully(serverNonce);
        int len = in.readInt();
        byte[] serverPubEnc = new byte[len];
        in.readFully(serverPubEnc);
        int sigLen = in.readInt();
        byte[] serverSignature = new byte[sigLen];
        in.readFully(serverSignature);

        if (!CryptoUtils.verify(sha256.digest(serverPubEnc), serverSignature, serverPublicKey)) {
            System.out.println("Firma server non valida. Chiusura.");
            socket.close();
            return;
        }

        byte[] serverDecoded = CryptoUtils.decryptRSA(serverPubEnc, clientPrivateKey);
        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec x509 = new X509EncodedKeySpec(serverDecoded);
        PublicKey serverPubKey = kf.generatePublic(x509);

        // Generazione chiave ECDH client
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256); // Usa curve standard tipo secp256r1
        KeyPair keyPair = kpg.generateKeyPair();

        // Invio chiave pubblica cifrata e firmata
        byte[] clientPubEnc = CryptoUtils.encryptRSA(keyPair.getPublic().getEncoded(), serverPublicKey);
        byte[] clientSignature = CryptoUtils.sign(sha256.digest(clientPubEnc), clientPrivateKey);
        out.writeInt(clientPubEnc.length);
        out.write(clientPubEnc);
        out.writeInt(clientSignature.length);
        out.write(clientSignature);

        // Calcolo chiave condivisa
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(keyPair.getPrivate());
        ka.doPhase(serverPubKey, true);
        byte[] sharedSecret = ka.generateSecret();

        // Derivazione chiave simmetrica da shared secret
        sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(sharedSecret);
        sha256.update(serverNonce); //nonce usato per evitare replay attack
        byte[] chachaKey = sha256.digest();

        SecretKey key = new SecretKeySpec(chachaKey, "ChaCha20");
       
        NonceGenerator nonceG = new NonceGenerator();
        Set<String> usedNonces = new HashSet<>();
        while(true) {
        	System.out.println("\n[Client] Inserisci un messaggio (o 'exit' per terminare): ");
            String message = scanner.nextLine();
            String compromised;
            
            if (message.trim().equalsIgnoreCase("exit")) break;
           
            do {
            	System.out.print("Vuoi simulare una compromissione? (s/n): ");
            	compromised = scanner.nextLine();
            }while(!compromised.trim().equalsIgnoreCase("s") && !compromised.trim().equalsIgnoreCase("n"));
            
            sendEncryptedMessage(out,key,message,compromised,nonceG);

            // Ricezione risposta cifrata
            String response = null;
            try{
               response = decryptMessage(in,key,usedNonces);
            }
            catch(ReplayAttackException r){
                System.out.println("Replay attacck rilevato, chiudo la connessione");
                socket.close();
                System.exit(0);
            }

            System.out.println("[Client] Risposta dal server: " + response);
            if(new String(response).equals("ACK")) {
            	System.out.println("Messaggio Inviato Correttamente!");
            }
            else {
            	System.out.println("Integrità Messaggio Compromesso!");
            }
        }

        socket.close();
    }
    
    private static void sendEncryptedMessage(DataOutputStream out, SecretKey key, String message,String compromised,NonceGenerator ng) throws Exception {
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
	    if (compromised.equalsIgnoreCase("s")) {
            ciphertext[0] ^= 0x01; // Altero l'integrità del messaggio
        }
	    out.write(nonce);
	    out.writeInt(ciphertext.length);
	    out.write(ciphertext);
	}
    
    private static String decryptMessage(DataInputStream in, SecretKey key,Set<String> usedNonces) throws Exception,ReplayAttackException {
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
    	
    	// Decifrazione
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
