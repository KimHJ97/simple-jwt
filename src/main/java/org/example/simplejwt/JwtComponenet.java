package org.example.simplejwt;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Objects;

import org.example.simplejwt.JWT.Algorithm;
import org.example.simplejwt.JwtAlgorithm.AlgorithmExecutor;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtComponenet {

	public static ObjectMapper objectMapper = new ObjectMapper();

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
			try {
				return objectMapper.writeValueAsString(this);
			} catch (JsonProcessingException e) {
				throw new RuntimeException(e);
			}
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
			try {
				System.out.println(objectMapper.writeValueAsString(this.claims));
				return objectMapper.writeValueAsString(this.claims);
			} catch (JsonProcessingException e) {
				throw new RuntimeException(e);
			}
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
			Object value = claims.get("expiraton");
			if (Objects.isNull(value)) {
				return null;
			}

			if (value instanceof Long expiraton) {
				Instant instant = Instant.ofEpochSecond(expiraton);
				return ZonedDateTime.ofInstant(instant, zoneId);
			} else if (value instanceof Integer expiraton) {
				Instant instant = Instant.ofEpochSecond(expiraton);
				return ZonedDateTime.ofInstant(instant, zoneId);
			}

			throw new RuntimeException("Expiration must be an instance of Long or Integer");
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

			throw new RuntimeException("NotBeforeAt must be an instance of Long or Integer");
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

			throw new RuntimeException("IssuedAt must be an instance of Long or Integer");
		}

		public <T> T getClaim(String claimName, Class<T> clazz) {
			Object value = claims.get(claimName);
			if (value == null) {
				return null;
			}
			if (clazz.isInstance(value)) {
				return (T)value;
			}
			throw new ClassCastException(claimName + " is not of type " + clazz.getName());
		}
	}

	/**
	 * JWT Signature
	 */
	public static class Signature {
		private String header;
		private String payload;
		private String secretkey;
		private Algorithm algorithm;
		private AlgorithmExecutor algorithmExecutor;

		public Signature(String header, String payload, String secretkey, Algorithm algorithm) {
			this.header = header;
			this.payload = payload;
			this.secretkey = secretkey;
			this.algorithm = algorithm;
			this.algorithmExecutor = new AlgorithmExecutor(algorithm, secretkey);
		}

		public byte[] toHash() {
			return this.algorithmExecutor.execute(header + "." + payload);
		}
	}

}
