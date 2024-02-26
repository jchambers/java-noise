# java-noise

This is mostly a personal sandbox for learning about [the Noise protocol framework](https://noiseprotocol.org/) and for thinking about what an ergonomic, Java-y Noise API might look like. At the time of writing, major test vectors pass, but a great deal is missing including tests, input validation and (perhaps most glaringly) documentation.

This project targets revision 34 of the [Noise specification](https://noiseprotocol.org/noise.html).

## Test vectors

Test vectors for this project come from several sources:

1. java-noise uses the test vectors from the [Cacophony](https://github.com/haskell-cryptography/cacophony) project without significant modification
2. java-noise uses parts of the "fallback" test vectors from the [noise-c](https://github.com/rweather/noise-c) project, but without the PSK-related fallback tests, since noise-c's PSK implementation appears to adhere to an earlier version of the Noise specification
3. Test vectors for the BLAKE2 algorithms come from the [BLAKE2](https://www.blake2.net/) project

The general idea behind Noise test vecors is [explained on the Noise wiki](https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors), though most publicly available test vectors seem to deviate from the format described on the wiki to some degree.
