// Fuzzes the compressed-fingerprint decoder, its header parser and the encode round trip.
// Input: [base64 flag][encoded fingerprint bytes...]
#include <chromaprint.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 1 || size > 0x7fffffff) {
		return -1;
	}
	const int base64 = data[0] & 1;
	const char *encoded = (const char *) data + 1;
	const int encoded_size = (int) (size - 1);

	int header_size = 0, header_algorithm = 0;
	const int header_ok = chromaprint_decode_fingerprint_header(encoded, encoded_size, &header_size, &header_algorithm, base64);

	uint32_t *fp = nullptr;
	int fp_size = 0, algorithm = 0;
	if (!chromaprint_decode_fingerprint(encoded, encoded_size, &fp, &fp_size, &algorithm, base64)) {
		return -1;
	}
	// A body that decodes also has a decodable header that agrees with it.
	if (!header_ok || header_size != fp_size || header_algorithm != algorithm) {
		abort();
	}

	uint32_t hash = 0;
	chromaprint_hash_fingerprint(fp, fp_size, &hash);

	// Re-encoding what was decoded must decode to the same fingerprint.
	char *re = nullptr;
	int re_size = 0;
	if (chromaprint_encode_fingerprint(fp, fp_size, algorithm, &re, &re_size, base64)) {
		uint32_t *fp2 = nullptr;
		int fp2_size = 0, algorithm2 = -1;
		if (!chromaprint_decode_fingerprint(re, re_size, &fp2, &fp2_size, &algorithm2, base64) ||
		    fp2_size != fp_size || algorithm2 != algorithm ||
		    (fp_size && memcmp(fp, fp2, sizeof(uint32_t) * fp_size) != 0)) {
			abort();
		}
		chromaprint_dealloc(fp2);
	}
	chromaprint_dealloc(re);
	chromaprint_dealloc(fp);
	return 0;
}
