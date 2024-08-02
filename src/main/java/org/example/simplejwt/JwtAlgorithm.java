package org.example.simplejwt;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.example.simplejwt.JWT.Algorithm;

public class JwtAlgorithm {

	/**
	 * 암호화 처리 실행 클래스
	 */
	public static class AlgorithmExecutor {

		private AlgorithmService algorithmService;

		public AlgorithmExecutor(Algorithm algorithm, String key) {
			this.algorithmService = switch (algorithm) {
				case HS256, HS384, HS512 -> new HmacAlgorithmService(algorithm, key);
				case RS256, RS384, RS512 -> new RsaAlgorithmService(algorithm, key);
				case ES256, ES384, ES512 -> new EcdsaAlgorithmService(algorithm, key);
				case PS256, PS384, PS512 -> new RsassaPssAlgorithmService(algorithm, key);
				default -> throw new RuntimeException("Unsupported algorithm: " + algorithm);
			};
		}

		public byte[] execute(String value) {
			return algorithmService.sign(value);
		}
	}

	/**
	 * 암호화 처리 인터페이스
	 */
	public interface AlgorithmService {
		byte[] sign(String value);

		default PrivateKey getPrivateKeyFromBase64(String key, String algorithm) {
			try {
				byte[] keyBytes = Base64.getDecoder().decode(key);
				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
				KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
				return keyFactory.generatePrivate(keySpec);
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
	}

	/**
	 * HMAC 암호화 구현체
	 */
	public static class HmacAlgorithmService implements AlgorithmService {
		private final Algorithm algorithm;
		private final String secretKey;

		public HmacAlgorithmService(Algorithm algorithm, String secretKey) {
			this.algorithm = algorithm;
			this.secretKey = secretKey;
		}

		@Override
		public byte[] sign(String data) {
			try {
				Mac mac = Mac.getInstance(algorithm.fullName());
				SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(secretKey),
					algorithm.fullName());
				mac.init(secretKeySpec);
				return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
			} catch (NoSuchAlgorithmException | InvalidKeyException e) {
				throw new RuntimeException(e);
			}
		}
	}

	/**
	 * RSA 암호화 구현체
	 */
	public static class RsaAlgorithmService implements AlgorithmService {
		private final Algorithm algorithm;
		private final PrivateKey privateKey;

		public RsaAlgorithmService(Algorithm algorithm, String privateKeyStr) {
			this.algorithm = algorithm;
			this.privateKey = getPrivateKeyFromBase64(privateKeyStr, algorithm.shortName());
		}

		@Override
		public byte[] sign(String data) {
			try {
				Signature signature = Signature.getInstance(algorithm.fullName());
				signature.initSign(privateKey);
				signature.update(data.getBytes(StandardCharsets.UTF_8));
				return signature.sign();
			} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
				throw new RuntimeException(e);
			}
		}
	}

	/**
	 * ECDSA 암호화 구현체
	 */
	public static class EcdsaAlgorithmService implements AlgorithmService {
		private final Algorithm algorithm;
		private final PrivateKey privateKey;

		public EcdsaAlgorithmService(Algorithm algorithm, String privateKeyStr) {
			this.algorithm = algorithm;
			this.privateKey = getPrivateKeyFromBase64(privateKeyStr, algorithm.shortName());
		}

		@Override
		public byte[] sign(String data) {
			try {
				Signature signature = Signature.getInstance(algorithm.fullName());
				signature.initSign(privateKey);
				signature.update(data.getBytes(StandardCharsets.UTF_8));
				return signature.sign();
			} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
				throw new RuntimeException(e);
			}
		}
	}

	/**
	 * RSASSA 암호화 구현체
	 */
	public static class RsassaPssAlgorithmService implements AlgorithmService {
		private final Algorithm algorithm;
		private final PrivateKey privateKey;

		public RsassaPssAlgorithmService(Algorithm algorithm, String privateKeyStr) {
			this.algorithm = algorithm;
			this.privateKey = getPrivateKeyFromBase64(privateKeyStr, algorithm.shortName());
		}

		@Override
		public byte[] sign(String data) {
			try {
				Signature signature = Signature.getInstance("RSASSA-PSS");
				signature.setParameter(
					new PSSParameterSpec(algorithm.fullName(), "MGF1", new MGF1ParameterSpec(algorithm.fullName()), 32,
						1));
				signature.initSign(privateKey);
				signature.update(data.getBytes(StandardCharsets.UTF_8));
				return signature.sign();
			} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException |
					 InvalidAlgorithmParameterException e) {
				throw new RuntimeException(e);
			}
		}
	}

}
