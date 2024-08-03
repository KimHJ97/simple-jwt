package org.example.simplejwt;

import static org.assertj.core.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;

import org.example.simplejwt.JWT.Algorithm;
import org.example.simplejwt.JwtComponenet.Header;
import org.example.simplejwt.JwtComponenet.Payload;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class JwtTest {

	public static final String HMAC256_SECRET_KEY = "DVQhGbZB20pzk1vRXxJLzxtlrWz5kkAIp84y0i+9MJo=";

	@Nested
	@DisplayName("JWT 생성 테스트")
	class JwtCreateTest {
		@Test
		@DisplayName("HMAC256 알고리즘을 사용한 JWT 생성")
		void createJwtWithHMAC256_success() throws Exception {
			String jwt = JWT.builder()
				.algorithm(Algorithm.HS256)
				.secretKey(HMAC256_SECRET_KEY)
				.issuer("김효준")
				.subject("subject")
				.issuedAt(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.expiration(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.build();

			assertThat(jwt).isNotEmpty();
			assertThat(jwt).isEqualTo(
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWJqZWN0Ijoic3ViamVjdCIsImV4cGlyYXRpb24iOjQxMDI0MTIzNDAsImlzc3VlZEF0Ijo0MTAyNDEyMzQwLCJpc3N1ZXIiOiLquYDtmqjspIAifQ.z9J-fUtKSPhXyyxTWSE3jKZicbiCeBgJzltGvhDMUSk");
		}

		@Test
		@DisplayName("SHA256withECDSA 알고리즘을 사용한 JWT 생성")
		void createJwtWithES256_success() throws Exception {
			PrivateKey privateKey = JWT.generateKeyPair(Algorithm.ES256, JWT.KeySize.LOW).getPrivate();

			String jwt = JWT.builder()
				.algorithm(Algorithm.ES256)
				.secretKey(privateKey)
				.issuer("김효준")
				.subject("subject")
				.issuedAt(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.expiration(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.build();

			assertThat(jwt).isNotEmpty();
		}

		@Test
		@DisplayName("SHA256withRSA 알고리즘을 사용한 JWT 생성")
		void createJwtWithRS256_success() throws Exception {
			PrivateKey privateKey = JWT.generateKeyPair(Algorithm.RS256, JWT.KeySize.LOW).getPrivate();

			String jwt = JWT.builder()
				.algorithm(Algorithm.RS256)
				.secretKey(privateKey)
				.issuer("김효준")
				.subject("subject")
				.issuedAt(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.expiration(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.build();

			assertThat(jwt).isNotEmpty();
		}
	}

	@Nested
	@DisplayName("JWT 생성 후 사용성 검증 테스트")
	class JwtUsageTeset {
		@Test
		@DisplayName("JWT 생성 후 헤더 추출")
		void parseJwtHeader_success() throws Exception {
			String token = JWT.builder()
				.algorithm(Algorithm.HS256)
				.secretKey(HMAC256_SECRET_KEY)
				.issuer("김효준")
				.subject("subject")
				.issuedAt(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.expiration(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.build();

			Header header = JWT.parser().signedKey(HMAC256_SECRET_KEY)
				.header(token);

			assertThat(header.getAlg()).isEqualTo(Algorithm.HS256.toString());
			assertThat(header.getTyp()).isEqualTo("JWT");
		}

		@Test
		@DisplayName("JWT 생성 후 페이로드 추출")
		void parseJwtPayload_success() throws Exception {
			String token = JWT.builder()
				.algorithm(Algorithm.HS256)
				.secretKey(HMAC256_SECRET_KEY)
				.issuer("김효준")
				.subject("subject")
				.claim("age", 20)
				.claim("isAdmin", true)
				.issuedAt(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.expiration(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.build();

			Payload payload = JWT.parser().signedKey(HMAC256_SECRET_KEY)
				.payload(token);

			assertThat(payload.getIssuer()).isEqualTo("김효준");
			assertThat(payload.getSubject()).isEqualTo("subject");
			assertThat(payload.getClaim("age", Integer.class)).isEqualTo(20);
			assertThat(payload.getClaim("isAdmin", Boolean.class)).isEqualTo(true);
			assertThat(payload.getIssuedAt(ZoneId.of("Asia/Seoul")))
				.isEqualTo(ZonedDateTime.of(LocalDateTime.of(2099, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")));
		}

		@Test
		@DisplayName("JWT 생성 후 페이로드 추출 실패 - 유효기간 만료")
		void parseJwtPayload_fail_expired() throws Exception {
			String token = JWT.builder()
				.algorithm(Algorithm.HS256)
				.secretKey(HMAC256_SECRET_KEY)
				.issuer("김효준")
				.subject("subject")
				.issuedAt(ZonedDateTime.of(LocalDateTime.of(2020, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.expiration(ZonedDateTime.of(LocalDateTime.of(2020, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.build();

			assertThatThrownBy(() -> {
				JWT.parser().signedKey(HMAC256_SECRET_KEY)
					.payload(token);
			}).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("The token has expired");
		}

		@Test
		@DisplayName("JWT 생성 후 페이로드 추출 실패 - SignedKey가 다름")
		void parseJwtPayload_fail_diffrentSignedKey() throws Exception {
			String diffrentSignedKey = Base64.getEncoder().encodeToString("diffrentSignedKey".getBytes(StandardCharsets.UTF_8));

			String token = JWT.builder()
				.algorithm(Algorithm.HS256)
				.secretKey(HMAC256_SECRET_KEY)
				.issuer("김효준")
				.subject("subject")
				.issuedAt(ZonedDateTime.of(LocalDateTime.of(2020, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.expiration(ZonedDateTime.of(LocalDateTime.of(2020, 12, 31, 23, 59), ZoneId.of("Asia/Seoul")))
				.build();

			assertThatThrownBy(() -> {
				JWT.parser().signedKey(diffrentSignedKey)
					.payload(token);
			}).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("Invalid JWT token");
		}
	}

}
