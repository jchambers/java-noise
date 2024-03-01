package com.eatthepath.noise;

/**
 * A Noise transport is a bidirectional reader and writer of Noise transport messages. In the terminology of the Noise
 * Protocol Framework specification, a {@code NoiseTransport} instance encapsulates the two "cipher states" produced by
 * "splitting" a {@link NoiseHandshake}.
 *
 * @see NoiseHandshake#toTransport()
 */
public interface NoiseTransport extends NoiseTransportReader, NoiseTransportWriter {
}
