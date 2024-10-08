package org.example.simplejwt;

import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

class JwtSupporter {
	public static ObjectMapper objectMapper = new ObjectMapper();
	public static Encoder base64UrlEncoderWithoutPadding = Base64.getUrlEncoder().withoutPadding();
	public static Encoder base64UrlEncoder = Base64.getUrlEncoder();
	public static Decoder base64UrlDecoder = Base64.getUrlDecoder();

	public static String writeValueAsString(Object value) {
		try {
			return objectMapper.writeValueAsString(value);
		} catch (JsonProcessingException e) {
			throw new JwtException(JwtException.JwtErrorCode.PARSING_ERROR, e);
		}
	}

	public static <T> T readValue(String value, Class<T> clazz) {
		try {
			return objectMapper.readValue(value, clazz);
		} catch (JsonProcessingException e) {
			throw new JwtException(JwtException.JwtErrorCode.PARSING_ERROR, e);
		}
	}

	public static String encodeBase64ToStringWithoutPadding(byte[] src) {
		return base64UrlEncoderWithoutPadding.encodeToString(src);
	}

	public static String encodeBase64ToString(byte[] src) {
		return base64UrlEncoder.encodeToString(src);
	}

	public static String decodeBase64ToString(String src, Charset charset) {
		return new String(base64UrlDecoder.decode(src), charset);
	}

	public static byte[] decodeBase64(String src) {
		return base64UrlDecoder.decode(src);
	}
}
