package org.example.simplejwt;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.example.simplejwt.JWT.Algorithm;
import org.example.simplejwt.JwtException.JwtErrorCode;

public class JwtAlgorithm {

	/**
	 * 암호화 처리 실행 클래스
	 */
	public static class AlgorithmExecutor {

		private AlgorithmService algorithmService;

		public AlgorithmExecutor(Algorithm algorithm, String key, AlgorithmKeyType keyType) {
			this.algorithmService = switch (algorithm) {
				case HS256, HS384, HS512 -> new HmacAlgorithmService(algorithm, key);
				case RS256, RS384, RS512 -> new RsaAlgorithmService(algorithm, key, keyType);
				case ES256, ES384, ES512 -> new EcdsaAlgorithmService(algorithm, key, keyType);
				case PS256, PS384, PS512 -> new RsassaPssAlgorithmService(algorithm, key, keyType);
				default -> throw new JwtException(JwtErrorCode.UNSUPPORTED_ALGORITHM, "Unsupported algorithm: " + algorithm);
			};
		}

		public byte[] execute(String value) {
			return algorithmService.sign(value);
		}

		public boolean verify(String data, String exprectedSignature) {
			return algorithmService.verify(data, exprectedSignature);
		}
	}

	/**
	 * 키 종류 구분 코드
	 *  - HMAC 알고리즘의 경우 SECRET_KEY만 사용
	 *  - RSA 알고리즘의 경우 암호화시 PRIVATE_KEY를 사용핳고, 복호화할 때는 PUBLIC_KEY를 사용
	 */
	public enum AlgorithmKeyType {
		SECRET_KEY,
		PRIVATE_KEY,
		PUBLIC_KEY;

		public static AlgorithmKeyType of(Algorithm algorithm, boolean isHashingProcess) {
			switch (algorithm) {
				case HS256, HS384, HS512 -> {
					return AlgorithmKeyType.SECRET_KEY;
				}
				case RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512 -> {
					if (isHashingProcess) {
						return AlgorithmKeyType.PRIVATE_KEY;
					} else {
						return AlgorithmKeyType.PUBLIC_KEY;
					}
				}
				default ->
					throw new JwtException(JwtErrorCode.UNSUPPORTED_ALGORITHM, "Unsupported algorithm: " + algorithm);
			}
		}
	}

	/**
	 * 암호화 처리 인터페이스
	 */
	public interface AlgorithmService {
		byte[] sign(String value);
		boolean verify(String data, String exprectedSignature);

		default PrivateKey getPrivateKeyFromBase64(String key, String algorithm) {
			try {
				byte[] keyBytes = JwtSupporter.decodeBase64(key);
				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
				KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
				return keyFactory.generatePrivate(keySpec);
			} catch (Exception e) {
				throw new JwtException(JwtErrorCode.SIGNATURE_ERROR, e);
			}
		}

		default PublicKey getPublicKeyFromBase64(String key, String algorithm) {
			try {
				byte[] keyBytes = JwtSupporter.decodeBase64(key);
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
				KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
				return keyFactory.generatePublic(keySpec);
			} catch (Exception e) {
				throw new JwtException(JwtErrorCode.SIGNATURE_ERROR, e);
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
				SecretKeySpec secretKeySpec = new SecretKeySpec(JwtSupporter.decodeBase64(secretKey),
					algorithm.fullName());
				mac.init(secretKeySpec);
				return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
			} catch (NoSuchAlgorithmException | InvalidKeyException e) {
				throw new JwtException(JwtErrorCode.SIGNATURE_ERROR, e);
			}
		}

		@Override
		public boolean verify(String data, String exprectedSignature) {
			byte[] hash = sign(data);
			String signature = JwtSupporter.encodeBase64ToStringWithoutPadding(hash);
			return signature.equals(exprectedSignature);
		}
	}

	/**
	 * RSA 암호화 구현체
	 */
	public static class RsaAlgorithmService implements AlgorithmService {
		private final Algorithm algorithm;
		private final Key key;

		public RsaAlgorithmService(Algorithm algorithm, String keyText, AlgorithmKeyType keyType) {
			this.algorithm = algorithm;
			if (keyType == AlgorithmKeyType.PRIVATE_KEY) {
				this.key = getPrivateKeyFromBase64(keyText, algorithm.shortName());
			} else {
				this.key = getPublicKeyFromBase64(keyText, algorithm.shortName());
			}
		}

		@Override
		public byte[] sign(String data) {
			try {
				Signature signature = Signature.getInstance(algorithm.fullName());
				signature.initSign((PrivateKey)key);
				signature.update(data.getBytes(StandardCharsets.UTF_8));
				return signature.sign();
			} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
				throw new JwtException(JwtErrorCode.SIGNATURE_ERROR, e);
			}
		}

		@Override
		public boolean verify(String data, String exprectedSignature) {
			try {
				Signature signature = Signature.getInstance(algorithm.fullName());
				signature.initVerify((PublicKey)key);
				signature.update(data.getBytes(StandardCharsets.UTF_8));
				return signature.verify(JwtSupporter.decodeBase64(exprectedSignature));
			} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
				throw new JwtException(JwtErrorCode.SIGNATURE_ERROR, e);
			}
		}
	}

	/**
	 * ECDSA 암호화 구현체
	 */
	public static class EcdsaAlgorithmService implements AlgorithmService {
		private final Algorithm algorithm;
		private final Key key;

		public EcdsaAlgorithmService(Algorithm algorithm, String keyText, AlgorithmKeyType keyType) {
			this.algorithm = algorithm;

			if (keyType == AlgorithmKeyType.PRIVATE_KEY) {
				this.key = getPrivateKeyFromBase64(keyText, algorithm.shortName());
			} else {
				this.key = getPublicKeyFromBase64(keyText, algorithm.shortName());
			}
		}

		@Override
		public byte[] sign(String data) {
			try {
				Signature signature = Signature.getInstance(algorithm.fullName());
				signature.initSign((PrivateKey)key);
				signature.update(data.getBytes(StandardCharsets.UTF_8));
				return signature.sign();
			} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
				throw new JwtException(JwtErrorCode.SIGNATURE_ERROR, e);
			}
		}

		@Override
		public boolean verify(String data, String exprectedSignature) {
			try {
				Signature signature = Signature.getInstance(algorithm.fullName());
				signature.initVerify((PublicKey)key);
				signature.update(data.getBytes(StandardCharsets.UTF_8));
				return signature.verify(JwtSupporter.decodeBase64(exprectedSignature));
			} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
				throw new JwtException(JwtErrorCode.SIGNATURE_ERROR, e);
			}
		}
	}

	/**
	 * RSASSA 암호화 구현체
	 */
	public static class RsassaPssAlgorithmService implements AlgorithmService {
		private final Algorithm algorithm;
		private final Key key;

		public RsassaPssAlgorithmService(Algorithm algorithm, String keyText, AlgorithmKeyType keyType) {
			this.algorithm = algorithm;
			if (keyType == AlgorithmKeyType.PRIVATE_KEY) {
				this.key = getPrivateKeyFromBase64(keyText, algorithm.shortName());
			} else {
				this.key = getPublicKeyFromBase64(keyText, algorithm.shortName());
			}
		}

		@Override
		public byte[] sign(String data) {
			try {
				Signature signature = Signature.getInstance("RSASSA-PSS");
				signature.setParameter(
					new PSSParameterSpec(algorithm.fullName(), "MGF1", new MGF1ParameterSpec(algorithm.fullName()), 32,
						1));
				signature.initSign((PrivateKey)key);
				signature.update(data.getBytes(StandardCharsets.UTF_8));
				return signature.sign();
			} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException |
					 InvalidAlgorithmParameterException e) {
				throw new JwtException(JwtErrorCode.SIGNATURE_ERROR, e);
			}
		}

		@Override
		public boolean verify(String data, String exprectedSignature) {
			try {
				Signature signature = Signature.getInstance("RSASSA-PSS");
				signature.setParameter(
					new PSSParameterSpec(algorithm.fullName(), "MGF1", new MGF1ParameterSpec(algorithm.fullName()), 32,
						1));
				signature.initVerify((PublicKey)key);
				signature.update(data.getBytes(StandardCharsets.UTF_8));
				return signature.verify(JwtSupporter.decodeBase64(exprectedSignature));
			} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException |
					 InvalidAlgorithmParameterException e) {
				throw new JwtException(JwtErrorCode.SIGNATURE_ERROR, e);
			}
		}
	}

}
