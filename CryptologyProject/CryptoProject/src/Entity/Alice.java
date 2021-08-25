package Entity;

import algorithm.Point;
import algorithm.EllipticCurveAlgorithm;
public class Alice {
	
	public static Point publicKey;
	private String privateKeyAlice = "55";
	EllipticCurveAlgorithm ECC = new EllipticCurveAlgorithm();

	
	public Alice() {
		
	}

	public Point getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(Point publicKey) {
		Alice.publicKey = publicKey;
	}

	public String getPrivateKeyAlice() {
		return privateKeyAlice;
	}


}
