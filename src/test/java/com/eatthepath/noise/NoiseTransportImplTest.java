package com.eatthepath.noise;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class NoiseTransportImplTest {

  private NoiseTransportImpl noiseTransport;

  @BeforeEach
  void setUp() throws NoSuchAlgorithmException, AEADBadTagException {
    final NoiseHandshake initiatorHandshake =
        NoiseHandshakeBuilder.forNNInitiator()
            .setComponentsFromProtocolName("Noise_NN_25519_AESGCM_SHA256")
            .build();

    final NoiseHandshake responderHandshake =
        NoiseHandshakeBuilder.forNNResponder()
            .setComponentsFromProtocolName("Noise_NN_25519_AESGCM_SHA256")
            .build();

    responderHandshake.readMessage(initiatorHandshake.writeMessage((byte[]) null));
    initiatorHandshake.readMessage(responderHandshake.writeMessage((byte[]) null));

    noiseTransport = (NoiseTransportImpl) initiatorHandshake.toTransport();
  }

  @Test
  void getPlaintextLength() {
    final int ciphertextLength = 77;
    assertEquals(ciphertextLength - 16, noiseTransport.getPlaintextLength(ciphertextLength));
  }

  @Test
  void getCiphertextLength() {
    final int plaintextLength = 83;
    assertEquals(plaintextLength + 16, noiseTransport.getCiphertextLength(plaintextLength));
  }

  @Test
  void writeMessageOversize() {
    // We want to make sure we're testing the size of the resulting message (which may include key material and AEAD
    // tags) rather than the length of just the payload
    final int plaintextLength = NoiseTransportImpl.MAX_NOISE_MESSAGE_SIZE - 1;
    final int messageLength = noiseTransport.getCiphertextLength(plaintextLength);

    assertTrue(messageLength > NoiseTransportImpl.MAX_NOISE_MESSAGE_SIZE);

    assertThrows(IllegalArgumentException.class,
        () -> noiseTransport.writeMessage(new byte[plaintextLength]));

    assertThrows(IllegalArgumentException.class,
        () -> noiseTransport.writeMessage(new byte[plaintextLength], 0, plaintextLength, new byte[messageLength], 0));

    assertThrows(IllegalArgumentException.class,
        () -> noiseTransport.writeMessage(ByteBuffer.allocate(plaintextLength)));

    assertThrows(IllegalArgumentException.class,
        () -> noiseTransport.writeMessage(ByteBuffer.allocate(plaintextLength), ByteBuffer.allocate(messageLength)));
  }

  @Test
  void writeMessageShortBuffer() {
    final byte[] plaintext = new byte[32];
    final byte[] message = new byte[noiseTransport.getCiphertextLength(plaintext.length) - 1];

    assertThrows(ShortBufferException.class, () ->
        noiseTransport.writeMessage(plaintext, 0, plaintext.length, message, 0));

    assertThrows(ShortBufferException.class, () ->
        noiseTransport.writeMessage(ByteBuffer.wrap(plaintext), ByteBuffer.wrap(message)));
  }

  @Test
  void readMessageOversize() throws NoSuchAlgorithmException {
    final int messageLength = NoiseTransportImpl.MAX_NOISE_MESSAGE_SIZE + 1;

    assertThrows(IllegalArgumentException.class, () ->
        noiseTransport.readMessage(new byte[messageLength]));

    assertThrows(IllegalArgumentException.class, () ->
        noiseTransport.readMessage(new byte[messageLength], 0, messageLength, new byte[messageLength], 0));

    assertThrows(IllegalArgumentException.class, () ->
        noiseTransport.readMessage(ByteBuffer.allocate(messageLength)));

    assertThrows(IllegalArgumentException.class, () ->
        noiseTransport.readMessage(ByteBuffer.allocate(messageLength), ByteBuffer.allocate(messageLength)));
  }

  @Test
  void readMessageShortBuffer() {
    final byte[] message = new byte[128];
    final int plaintextLength = noiseTransport.getPlaintextLength(message.length);

    assertThrows(ShortBufferException.class, () ->
        noiseTransport.readMessage(message, 0, message.length, new byte[plaintextLength - 1], 0));

    assertThrows(ShortBufferException.class, () ->
        noiseTransport.readMessage(ByteBuffer.wrap(message), ByteBuffer.allocate(plaintextLength - 1)));
  }
}