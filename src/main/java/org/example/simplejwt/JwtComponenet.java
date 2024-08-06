package org.example.simplejwt;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Objects;

import org.example.simplejwt.JWT.Algorithm;
import org.example.simplejwt.JwtAlgorithm.AlgorithmExecutor;
import org.example.simplejwt.JwtAlgorithm.AlgorithmKeyType;
import org.example.simplejwt.JwtException.JwtErrorCode;

public class JwtComponenet {

	/**
	 * JWT Header
	 */
	public static class Header {
		private String alg;
		private String typ = "JWT";

		private Header() {
		}

		public Header(Algorithm alg) {
			this.alg = alg.toString();
		}

		public String toJson() {
			return JwtSupporter.writeValueAsString(this);
		}

		public String getAlg() {
			return alg;
		}

		public String getTyp() {
			return typ;
		}
	}

	/**
	 * JWT Payload
	 */
	public static class Payload {
		private Map<String, Object> claims;

		public Payload(Map<String, Object> claims) {
			this.claims = claims;
		}

		public String toJson() {
			return JwtSupporter.writeValueAsString(this.claims);
		}

		public String getIssuer() {
			Object value = claims.get("issuer");
			return value == null ? null : value.toString();
		}

		public String getSubject() {
			Object value = claims.get("subject");
			return value == null ? null : value.toString();
		}

		public String getAudience() {
			Object value = claims.get("audience");
			return value == null ? null : value.toString();
		}

		public ZonedDateTime getExpiration(ZoneId zoneId) {
			Object value = claims.get("expiration");
			if (Objects.isNull(value)) {
				return null;
			}

			if (value instanceof Long expiration) {
				Instant instant = Instant.ofEpochSecond(expiration);
				return ZonedDateTime.ofInstant(instant, zoneId);
			} else if (value instanceof Integer expiration) {
				Instant instant = Instant.ofEpochSecond(expiration);
				return ZonedDateTime.ofInstant(instant, zoneId);
			}

			throw new JwtException(JwtErrorCode.PARSING_ERROR, "Expiration must be an instance of Long or Integer");
		}

		public ZonedDateTime getNotBeforeAt(ZoneId zoneId) {
			Object value = claims.get("notBeforeAt");
			if (Objects.isNull(value)) {
				return null;
			}

			if (value instanceof Long notBeforeAt) {
				Instant instant = Instant.ofEpochSecond(notBeforeAt);
				return ZonedDateTime.ofInstant(instant, zoneId);
			} else if (value instanceof Integer notBeforeAt) {
				Instant instant = Instant.ofEpochSecond(notBeforeAt);
				return ZonedDateTime.ofInstant(instant, zoneId);
			}

			throw new JwtException(JwtErrorCode.PARSING_ERROR, "NotBeforeAt must be an instance of Long or Integer");
		}

		public ZonedDateTime getIssuedAt(ZoneId zoneId) {
			Object value = claims.get("issuedAt");
			if (Objects.isNull(value)) {
				return null;
			}

			if (value instanceof Long issuedAt) {
				Instant instant = Instant.ofEpochSecond(issuedAt);
				return ZonedDateTime.ofInstant(instant, zoneId);
			} else if (value instanceof Integer issuedAt) {
				Instant instant = Instant.ofEpochSecond(issuedAt);
				return ZonedDateTime.ofInstant(instant, zoneId);
			}

			throw new JwtException(JwtErrorCode.PARSING_ERROR, "IssuedAt must be an instance of Long or Integer");
		}

		public <T> T getClaim(String claimName, Class<T> clazz) {
			Object value = claims.get(claimName);
			if (value == null) {
				return null;
			}
			if (clazz.isInstance(value)) {
				return (T)value;
			}
			throw new JwtException(JwtErrorCode.CLASS_CAST_ERROR, claimName + " is not of type " + clazz.getName());
		}
	}

	/**
	 * JWT Signature
	 */
	public static class Signature {
		private String header;
		private String payload;
		private String key;
		private Algorithm algorithm;
		private AlgorithmExecutor algorithmExecutor;

		public Signature(String header, String payload, String key, Algorithm algorithm) {
			this.header = header;
			this.payload = payload;
			this.key = key;
			this.algorithm = algorithm;
			this.algorithmExecutor = new AlgorithmExecutor(algorithm, key, AlgorithmKeyType.of(algorithm, true));
		}

		public byte[] toHash() {
			return this.algorithmExecutor.execute(header + "." + payload);
		}
	}

}
