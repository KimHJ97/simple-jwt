package org.example.simplejwt;

import java.security.KeyPair;
import java.util.Objects;

import javax.crypto.SecretKey;

import org.example.simplejwt.JwtException.JwtErrorCode;

public class JWT {

	/**
	 * JWT 생성 빌더
	 * @return JwtBuilder
	 */
	public static JwtBuilder builder() {
		return new JwtBuilder();
	}

	/**
	 * JWT 토큰 파서
	 * @return JwtParser
	 */
	public static JwtParser parser() {
		return new JwtParser();
	}

	/**
	 * HS 알고리즘 시크릿 키 생성
	 * @param algorithm
	 * @return
	 */
	public static SecretKey generateSecretKey(Algorithm algorithm) {
		return switch (algorithm) {
			case HS256, HS384, HS512 -> JwtKeyGenerator.generateHmacSecretKey(algorithm.fullName);
			default -> throw new JwtException(JwtErrorCode.UNSUPPORTED_ALGORITHM);
		};
	}

	/**
	 * RSA, EC 키 쌍(개인키, 공개키) 생성
	 * @param algorithm
	 * @param keySize
	 * @return
	 */
	public static KeyPair generateKeyPair(Algorithm algorithm, KeySize keySize) {
		if (Objects.isNull(algorithm)) {
			throw new JwtException(JwtErrorCode.ALGORITHM_REQUIRED);
		}
		if (Objects.isNull(keySize)) {
			throw new JwtException(JwtErrorCode.KEY_SIZE_REQUIRED);
		}

		return switch (algorithm) {
			case RS256, RS384, RS512,
				 PS256, PS384, PS512 -> JwtKeyGenerator.generateRsaKeyPair(algorithm.shortName, keySize.size);
			case ES256, ES384, ES512 -> JwtKeyGenerator.generateEcdsaKeyPair(algorithm.shortName, keySize.size);
			default -> throw new JwtException(JwtErrorCode.UNSUPPORTED_ALGORITHM);
		};
	}

	/**
	 * JWT 알고리즘
	 */
	public enum Algorithm {
		HS256("HS", "HmacSHA256"),
		HS384("HS", "HmacSHA384"),
		HS512("HS", "HmacSHA512"),
		RS256("RSA", "SHA256withRSA"),
		RS384("RSA", "SHA384withRSA"),
		RS512("RSA", "SHA512withRSA"),
		ES256("EC", "SHA256withECDSA"),
		ES384("EC", "SHA384withECDSA"),
		ES512("EC", "SHA256withECDSA"),
		PS256("RSA", "SHA-256"),
		PS384("RSA", "SHA-384"),
		PS512("RSA", "SHA-512");

		private final String shortName;
		private final String fullName;

		Algorithm(String shortName, String fullName) {
			this.shortName = shortName;
			this.fullName = fullName;
		}

		public String shortName() {
			return shortName;
		}

		public String fullName() {
			return fullName;
		}
	}

	/**
	 * JWT 알고리즘 키 사이즈
	 */
	public enum KeySize {
		HIGH(4096),
		MIDDLE(3072),
		LOW(2048);

		private final int size;

		KeySize(int size) {
			this.size = size;
		}

		public int size() {
			return size;
		}
	}

}
