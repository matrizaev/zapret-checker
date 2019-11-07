#define PKCS11_LIBRARY_NAME "librtpkcs11ecp.so"
#define arraysize(a)                (sizeof(a) / sizeof(a[0]))

extern char *SigningPerform (void *inData, size_t inputLength, size_t *outputLength, uint8_t *userPIN, size_t userPINLen, uint8_t *keyPairId, size_t keyPairIdLen);

