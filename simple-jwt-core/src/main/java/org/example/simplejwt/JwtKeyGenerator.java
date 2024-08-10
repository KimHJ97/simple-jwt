package org.example.simplejwt;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.example.simplejwt.JwtException.JwtErrorCode;

public class JwtKeyGenerator {

	public static KeyPair generateRsaKeyPair(String algorithm, int keySize) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
			keyPairGenerator.initialize(keySize);

			return keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new JwtException(JwtErrorCode.KEY_GENERATION_FAILURE, e, "Error generating RSA key pair");
		}
	}

	public static KeyPair generateEcdsaKeyPair(String algorithm, int keySize) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
			ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
			keyPairGenerator.initialize(ecSpec);

			return keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new JwtException(JwtErrorCode.KEY_GENERATION_FAILURE, e, "Error generating EC key pair");
		}
	}

	public static SecretKey generateHmacSecretKey(String algorithm) {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
			return keyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			throw new JwtException(JwtErrorCode.KEY_GENERATION_FAILURE, e, "Error generating HMAC key");
		}
	}
}
