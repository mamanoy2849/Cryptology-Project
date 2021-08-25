package Entity;

import algorithm.Point;
import algorithm.EllipticCurveAlgorithm;
public class Bob {

	public static Point publicKey;
	private String privateKeyBob = "75";
	EllipticCurveAlgorithm ECC = new EllipticCurveAlgorithm();
	public byte[] signatur;
	public static byte[] aliceEncryptedKey;
	
	public Bob() {

	}


	public Point getPublicKey() {
		return publicKey;
	}


	public void setPublicKey(Point publicKey) {
		Bob.publicKey = publicKey;
	}


	public String getPrivateKeyBob() {
		return privateKeyBob;
	}

	
	//publish signatur.
	public void setSignature(byte[] signatur) {
		
		this.signatur = signatur;
		
	}
	
	public byte[] getSignature() {
		
		return this.signatur;
		
	}


	public void setKey(byte[] encrypt) {
		
		aliceEncryptedKey = encrypt;
		
	}
	
	
	
	public byte[] getKey() {
		
		return aliceEncryptedKey;
	}
}
