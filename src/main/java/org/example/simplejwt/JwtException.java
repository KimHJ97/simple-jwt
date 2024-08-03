package org.example.simplejwt;

public class JwtException extends RuntimeException {

	private final JwtErrorCode errorCode;

	public JwtException(JwtErrorCode errorCode) {
		super(errorCode.getMessage());
		this.errorCode = errorCode;
	}

	public JwtException(JwtErrorCode errorCode, String errorMessage) {
		super(errorMessage);
		this.errorCode = errorCode;
	}

	public JwtException(JwtErrorCode errorCode, Throwable cause) {
		super(errorCode.getMessage(), cause);
		this.errorCode = errorCode;
	}

	public JwtException(JwtErrorCode errorCode, Throwable cause, String errorMessage) {
		super(errorMessage, cause);
		this.errorCode = errorCode;
	}

	public JwtErrorCode getErrorCode() {
		return errorCode;
	}

	public enum JwtErrorCode {
		INVALID_TOKEN("The token is invalid."),
		EXPIRED_TOKEN("The token has expired."),
		NOT_BEFORE_TOKEN("The token cannot be used before the specified time."),
		UNSUPPORTED_TOKEN("The token type is not supported."),
		MALFORMED_TOKEN("The token is malformed."),
		INVALID_SIGNATURE("The token signature is invalid."),
		INVALID_CLAIMS("The token claims are invalid."),
		KEY_GENERATION_ERROR("Error occurred during key generation."),
		PARSING_ERROR("Error occurred during token parsing."),
		SECRET_KEY_REQUIRED("The SecretKey is required."),
		ALGORITHM_REQUIRED("The Algorithm is required."),
		KEY_SIZE_REQUIRED("The Key Size is required."),
		SIGNED_KEY_REQUIRED("The Signed Key is required."),
		UNSUPPORTED_ALGORITHM("The algorithm is not supported."),
		KEY_GENERATION_FAILURE("Error occurred during key generation."),
		SIGNATURE_ERROR("Error occurred during signature generation."),
		CLASS_CAST_ERROR("Error occurred during class cast."),
		UNKNOWN_ERROR("An unknown error occurred.");

		private final String message;

		JwtErrorCode(String message) {
			this.message = message;
		}

		public String getMessage() {
			return message;
		}
	}

}
