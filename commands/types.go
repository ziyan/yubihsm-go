package commands

type (
	CommandType uint8
	ErrorCode   uint8
	Algorithm   uint8
)

const (
	ResponseCommandOffset = 0x80
	ErrorResponseCode     = 0xff

	// LabelLength is the max length of a label
	LabelLength = 40

	CommandTypeEcho                    CommandType = 0x01
	CommandTypeCreateSession           CommandType = 0x03
	CommandTypeAuthenticateSession     CommandType = 0x04
	CommandTypeSessionMessage          CommandType = 0x05
	CommandTypeDeviceInfo              CommandType = 0x06
	CommandTypeReset                   CommandType = 0x08
	CommandTypeCloseSession            CommandType = 0x40
	CommandTypeStorageStatus           CommandType = 0x41
	CommandTypePutOpaque               CommandType = 0x42
	CommandTypeGetOpaque               CommandType = 0x43
	CommandTypePutAuthKey              CommandType = 0x44
	CommandTypePutAsymmetric           CommandType = 0x45
	CommandTypeGenerateAsymmetricKey   CommandType = 0x46
	CommandTypeSignDataPkcs1           CommandType = 0x47
	CommandTypeListObjects             CommandType = 0x48
	CommandTypeDecryptPkcs1            CommandType = 0x49
	CommandTypeExportWrapped           CommandType = 0x4a
	CommandTypeImportWrapped           CommandType = 0x4b
	CommandTypePutWrapKey              CommandType = 0x4c
	CommandTypeGetLogs                 CommandType = 0x4d
	CommandTypeGetObjectInfo           CommandType = 0x4e
	CommandTypePutOption               CommandType = 0x4f
	CommandTypeGetOption               CommandType = 0x50
	CommandTypeGetPseudoRandom         CommandType = 0x51
	CommandTypePutHMACKey              CommandType = 0x52
	CommandTypeHMACData                CommandType = 0x53
	CommandTypeGetPubKey               CommandType = 0x54
	CommandTypeSignDataPss             CommandType = 0x55
	CommandTypeSignDataEcdsa           CommandType = 0x56
	CommandTypeDecryptEcdh             CommandType = 0x57 // here for backwards compatibility
	CommandTypeDeriveEcdh              CommandType = 0x57
	CommandTypeDeleteObject            CommandType = 0x58
	CommandTypeDecryptOaep             CommandType = 0x59
	CommandTypeGenerateHMACKey         CommandType = 0x5a
	CommandTypeGenerateWrapKey         CommandType = 0x5b
	CommandTypeVerifyHMAC              CommandType = 0x5c
	CommandTypeOTPDecrypt              CommandType = 0x60
	CommandTypeOTPAeadCreate           CommandType = 0x61
	CommandTypeOTPAeadRandom           CommandType = 0x62
	CommandTypeOTPAeadRewrap           CommandType = 0x63
	CommandTypeAttestAsymmetric        CommandType = 0x64
	CommandTypePutOTPAeadKey           CommandType = 0x65
	CommandTypeGenerateOTPAeadKey      CommandType = 0x66
	CommandTypeSetLogIndex             CommandType = 0x67
	CommandTypeWrapData                CommandType = 0x68
	CommandTypeUnwrapData              CommandType = 0x69
	CommandTypeSignDataEddsa           CommandType = 0x6a
	CommandTypeSetBlink                CommandType = 0x6b
	CommandTypeChangeAuthenticationKey CommandType = 0x6c

	// Errors
	ErrorCodeOK                ErrorCode = 0x00
	ErrorCodeInvalidCommand    ErrorCode = 0x01
	ErrorCodeInvalidData       ErrorCode = 0x02
	ErrorCodeInvalidSession    ErrorCode = 0x03
	ErrorCodeAuthFail          ErrorCode = 0x04
	ErrorCodeSessionFull       ErrorCode = 0x05
	ErrorCodeSessionFailed     ErrorCode = 0x06
	ErrorCodeStorageFailed     ErrorCode = 0x07
	ErrorCodeWrongLength       ErrorCode = 0x08
	ErrorCodeInvalidPermission ErrorCode = 0x09
	ErrorCodeLogFull           ErrorCode = 0x0a
	ErrorCodeObjectNotFound    ErrorCode = 0x0b
	ErrorCodeIDIllegal         ErrorCode = 0x0c
	ErrorCodeCommandUnexecuted ErrorCode = 0xff

	// Algorithms
	AlgorithmP256                    Algorithm = 12
	AlgorithmSecp256k1               Algorithm = 15
	AlgorithmYubicoAESAuthentication Algorithm = 38
	AlgorighmED25519                 Algorithm = 46

	// Copied from lib/yubihsm.h
	AlgorithmRsaPkcs1Sha1               Algorithm = 1  /// rsa-pkcs1-sha1
	AlgorithmRsaPkcs1Sha256             Algorithm = 2  /// rsa-pkcs1-sha256
	AlgorithmRsaPkcs1Sha384             Algorithm = 3  /// rsa-pkcs1-sha384
	AlgorithmRsaPkcs1Sha512             Algorithm = 4  /// rsa-pkcs1-sha512
	AlgorithmRsaPssSha1                 Algorithm = 5  /// rsa-pss-sha1
	AlgorithmRsaPssSha256               Algorithm = 6  /// rsa-pss-sha256
	AlgorithmRsaPssSha384               Algorithm = 7  /// rsa-pss-sha384
	AlgorithmRsaPssSha512               Algorithm = 8  /// rsa-pss-sha512
	AlgorithmRsa2048                    Algorithm = 9  /// rsa2048
	AlgorithmRsa3072                    Algorithm = 10 /// rsa3072
	AlgorithmRsa4096                    Algorithm = 11 /// rsa4096
	AlgorithmEcP256                     Algorithm = 12 /// ecp256
	AlgorithmEcP384                     Algorithm = 13 /// ecp384
	AlgorithmEcP521                     Algorithm = 14 /// ecp521
	AlgorithmEcK256                     Algorithm = 15 /// eck256
	AlgorithmEcBp256                    Algorithm = 16 /// ecbp256
	AlgorithmEcBp384                    Algorithm = 17 /// ecbp384
	AlgorithmEcBp512                    Algorithm = 18 /// ecbp512
	AlgorithmHmacSha1                   Algorithm = 19 /// hmac-sha1
	AlgorithmHmacSha256                 Algorithm = 20 /// hmac-sha256
	AlgorithmHmacSha384                 Algorithm = 21 /// hmac-sha384
	AlgorithmHmacSha512                 Algorithm = 22 /// hmac-sha512
	AlgorithmEcEcdsaSha1                Algorithm = 23 /// ecdsa-sha1
	AlgorithmEcEcdh                     Algorithm = 24 /// ecdh
	AlgorithmRsaOaepSha1                Algorithm = 25 /// rsa-oaep-sha1
	AlgorithmRsaOaepSha256              Algorithm = 26 /// rsa-oaep-sha256
	AlgorithmRsaOaepSha384              Algorithm = 27 /// rsa-oaep-sha384
	AlgorithmRsaOaepSha512              Algorithm = 28 /// rsa-oaep-sha512
	AlgorithmAes128CcmWrap              Algorithm = 29 /// aes128-ccm-wrap
	AlgorithmOpaqueData                 Algorithm = 30 /// opaque-data
	AlgorithmOpaqueX509Certificate      Algorithm = 31 /// opaque-x509-certificate
	AlgorithmMgf1Sha1                   Algorithm = 32 /// mgf1-sha1
	AlgorithmMgf1Sha256                 Algorithm = 33 /// mgf1-sha256
	AlgorithmMgf1Sha384                 Algorithm = 34 /// mgf1-sha384
	AlgorithmMgf1Sha512                 Algorithm = 35 /// mgf1-sha512
	AlgorithmTemplateSsh                Algorithm = 36 /// template-ssh
	AlgorithmAes128YubicoOtp            Algorithm = 37 /// aes128-yubico-otp
	AlgorithmAes128YubicoAuthentication Algorithm = 38 /// aes128-yubico-authentication
	AlgorithmAes192YubicoOtp            Algorithm = 39 /// aes192-yubico-otp
	AlgorithmAes256YubicoOtp            Algorithm = 40 /// aes256-yubico-otp
	AlgorithmAes192CcmWrap              Algorithm = 41 /// aes192-ccm-wrap
	AlgorithmAes256CcmWrap              Algorithm = 42 /// aes256-ccm-wrap
	AlgorithmEcEcdsaSha256              Algorithm = 43 /// ecdsa-sha256
	AlgorithmEcEcdsaSha384              Algorithm = 44 /// ecdsa-sha384
	AlgorithmEcEcdsaSha512              Algorithm = 45 /// ecdsa-sha512
	AlgorithmEcEd25519                  Algorithm = 46 /// ed25519
	AlgorithmEcP224                     Algorithm = 47 /// ecp224

	// Capabilities
	CapabilityGetOpaque             uint64 = 0x0000000000000001
	CapabilityPutOpaque             uint64 = 0x0000000000000002
	CapabilityPutAuthKey            uint64 = 0x0000000000000004
	CapabilityPutAsymmetric         uint64 = 0x0000000000000008
	CapabilityAsymmetricGen         uint64 = 0x0000000000000010
	CapabilityAsymmetricSignPkcs    uint64 = 0x0000000000000020
	CapabilityAsymmetricSignPss     uint64 = 0x0000000000000040
	CapabilityAsymmetricSignEcdsa   uint64 = 0x0000000000000080
	CapabilityAsymmetricSignEddsa   uint64 = 0x0000000000000100
	CapabilityAsymmetricDecryptPkcs uint64 = 0x0000000000000200
	CapabilityAsymmetricDecryptOaep uint64 = 0x0000000000000400
	CapabilityAsymmetricDecryptEcdh uint64 = 0x0000000000000800 // here for backwards compatibility
	CapabilityAsymmetricDeriveEcdh  uint64 = 0x0000000000000800
	CapabilityExportWrapped         uint64 = 0x0000000000001000
	CapabilityImportWrapped         uint64 = 0x0000000000002000
	CapabilityPutWrapKey            uint64 = 0x0000000000004000
	CapabilityGenerateWrapKey       uint64 = 0x0000000000008000
	CapabilityExportUnderWrap       uint64 = 0x0000000000010000
	CapabilityPutOption             uint64 = 0x0000000000020000
	CapabilityGetOption             uint64 = 0x0000000000040000
	CapabilityGetRandomness         uint64 = 0x0000000000080000
	CapabilityPutHmacKey            uint64 = 0x0000000000100000
	CapabilityHmacKeyGenerate       uint64 = 0x0000000000200000
	CapabilityHmacData              uint64 = 0x0000000000400000
	CapabilityHmacVerify            uint64 = 0x0000000000800000
	CapabilityAudit                 uint64 = 0x0000000001000000
	CapabilitySshCertify            uint64 = 0x0000000002000000
	CapabilityGetTemplate           uint64 = 0x0000000004000000
	CapabilityPutTemplate           uint64 = 0x0000000008000000
	CapabilityReset                 uint64 = 0x0000000010000000
	CapabilityOtpDecrypt            uint64 = 0x0000000020000000
	CapabilityOtpAeadCreate         uint64 = 0x0000000040000000
	CapabilityOtpAeadRandom         uint64 = 0x0000000080000000
	CapabilityOtpAeadRewrapFrom     uint64 = 0x0000000100000000
	CapabilityOtpAeadRewrapTo       uint64 = 0x0000000200000000
	CapabilityAttest                uint64 = 0x0000000400000000
	CapabilityPutOtpAeadKey         uint64 = 0x0000000800000000
	CapabilityGenerateOtpAeadKey    uint64 = 0x0000001000000000
	CapabilityWrapData              uint64 = 0x0000002000000000
	CapabilityUnwrapData            uint64 = 0x0000004000000000
	CapabilityDeleteOpaque          uint64 = 0x0000008000000000
	CapabilityDeleteAuthKey         uint64 = 0x0000010000000000
	CapabilityDeleteAsymmetric      uint64 = 0x0000020000000000
	CapabilityDeleteWrapKey         uint64 = 0x0000040000000000
	CapabilityDeleteHmacKey         uint64 = 0x0000080000000000
	CapabilityDeleteTemplate        uint64 = 0x0000100000000000
	CapabilityDeleteOtpAeadKey      uint64 = 0x0000200000000000

	// Domains
	Domain1  uint16 = 0x0001
	Domain2  uint16 = 0x0002
	Domain3  uint16 = 0x0004
	Domain4  uint16 = 0x0008
	Domain5  uint16 = 0x0010
	Domain6  uint16 = 0x0020
	Domain7  uint16 = 0x0040
	Domain8  uint16 = 0x0080
	Domain9  uint16 = 0x0100
	Domain10 uint16 = 0x0200
	Domain11 uint16 = 0x0400
	Domain12 uint16 = 0x0800
	Domain13 uint16 = 0x1000
	Domain14 uint16 = 0x2000
	Domain15 uint16 = 0x4000
	Domain16 uint16 = 0x8000

	// object types
	ObjectTypeOpaque            uint8 = 0x01
	ObjectTypeAuthenticationKey uint8 = 0x02
	ObjectTypeAsymmetricKey     uint8 = 0x03
	ObjectTypeWrapKey           uint8 = 0x04
	ObjectTypeHmacKey           uint8 = 0x05
	ObjectTypeTemplate          uint8 = 0x06
	ObjectTypeOtpAeadKey        uint8 = 0x07

	// list objects params
	ListObjectParamID   uint8 = 0x01
	ListObjectParamType uint8 = 0x02
)
