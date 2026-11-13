// Fuzzes the audio -> fingerprint pipeline of the public API.
// Input: [algorithm][sample_rate LE16][channels][chunk][silence_threshold][int16 PCM samples...]
#include <chromaprint.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 6) {
		return -1;
	}
	const int algorithm = data[0];
	// chromaprint.h: ChromaprintAlgorithm is CHROMAPRINT_ALGORITHM_TEST1..TEST5.
	if (algorithm > CHROMAPRINT_ALGORITHM_TEST5) {
		return -1;
	}
	const int sample_rate = data[1] | (data[2] << 8);
	const int num_channels = data[3];
	// chromaprint.h: num_channels is the channel count of the interleaved input; the library needs >= 1.
	if (num_channels == 0 || num_channels > 8) {
		return -1;
	}
	const int chunk = data[4] + 1;
	const int silence_threshold = data[5];

	const size_t num_samples = (size - 6) / sizeof(int16_t);
	std::vector<int16_t> samples(num_samples);
	if (num_samples) {
		memcpy(samples.data(), data + 6, num_samples * sizeof(int16_t));
	}

	ChromaprintContext *ctx = chromaprint_new(algorithm);
	if (!ctx) {
		return -1;
	}
	chromaprint_set_option(ctx, "silence_threshold", silence_threshold);
	if (!chromaprint_start(ctx, sample_rate, num_channels)) {
		chromaprint_free(ctx);
		return -1;
	}
	for (size_t i = 0; i < num_samples; i += chunk) {
		const size_t n = num_samples - i < (size_t) chunk ? num_samples - i : (size_t) chunk;
		chromaprint_feed(ctx, samples.data() + i, (int) n);
	}
	chromaprint_finish(ctx);

	char *fp = nullptr;
	uint32_t *raw = nullptr;
	int raw_size = 0;
	uint32_t hash = 0;
	if (chromaprint_get_fingerprint(ctx, &fp) && chromaprint_get_raw_fingerprint(ctx, &raw, &raw_size)) {
		chromaprint_get_fingerprint_hash(ctx, &hash);
		// The compressed fingerprint must decode back to the raw one.
		uint32_t *dec = nullptr;
		int dec_size = 0, dec_algorithm = -1;
		if (!chromaprint_decode_fingerprint(fp, (int) strlen(fp), &dec, &dec_size, &dec_algorithm, 1) ||
		    dec_size != raw_size || dec_algorithm != algorithm ||
		    (raw_size && memcmp(dec, raw, sizeof(uint32_t) * raw_size) != 0)) {
			abort();
		}
		chromaprint_dealloc(dec);
	}
	chromaprint_dealloc(fp);
	chromaprint_dealloc(raw);
	chromaprint_clear_fingerprint(ctx);
	chromaprint_free(ctx);
	return 0;
}
