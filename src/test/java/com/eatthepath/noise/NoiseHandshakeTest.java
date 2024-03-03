package com.eatthepath.noise;

import com.eatthepath.noise.component.NoiseKeyAgreement;
import org.junit.jupiter.api.Test;

import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class NoiseHandshakeTest {

  @Test
  void getOutboundMessageLength() throws NoSuchPatternException {
    final HandshakePattern handshakePattern = HandshakePattern.getInstance("XX");

    final int publicKeyLength = 56;

    // Expected lengths via https://noiseprotocol.org/noise.html#message-format
    assertEquals(56, NoiseHandshake.getOutboundMessageLength(handshakePattern, 0, publicKeyLength, 0));
    assertEquals(144, NoiseHandshake.getOutboundMessageLength(handshakePattern, 1, publicKeyLength, 0));
    assertEquals(88, NoiseHandshake.getOutboundMessageLength(handshakePattern, 2, publicKeyLength, 0));

    assertEquals(59, NoiseHandshake.getOutboundMessageLength(handshakePattern, 0, publicKeyLength, 3));
    assertEquals(149, NoiseHandshake.getOutboundMessageLength(handshakePattern, 1, publicKeyLength, 5));
    assertEquals(95, NoiseHandshake.getOutboundMessageLength(handshakePattern, 2, publicKeyLength, 7));
  }

  @Test
  void getPayloadLength() throws NoSuchPatternException {
    final HandshakePattern handshakePattern = HandshakePattern.getInstance("XX");

    final int publicKeyLength = 56;

    // Expected lengths via https://noiseprotocol.org/noise.html#message-format
    assertEquals(0, NoiseHandshake.getPayloadLength(handshakePattern, 0, publicKeyLength, 56));
    assertEquals(0, NoiseHandshake.getPayloadLength(handshakePattern, 1, publicKeyLength, 144));
    assertEquals(0, NoiseHandshake.getPayloadLength(handshakePattern, 2, publicKeyLength, 88));

    assertEquals(3, NoiseHandshake.getPayloadLength(handshakePattern, 0, publicKeyLength, 59));
    assertEquals(5, NoiseHandshake.getPayloadLength(handshakePattern, 1, publicKeyLength, 149));
    assertEquals(7, NoiseHandshake.getPayloadLength(handshakePattern, 2, publicKeyLength, 95));

    assertThrows(IllegalArgumentException.class,
        () -> NoiseHandshake.getPayloadLength(handshakePattern, 0, publicKeyLength, 55));
  }

  @Test
  void writeMessageOversize() throws NoSuchAlgorithmException {
    final NoiseKeyAgreement keyAgreement = NoiseKeyAgreement.getInstance("25519");

    final NoiseHandshake handshake =
        NoiseHandshakeBuilder.forIKInitiator(keyAgreement.generateKeyPair(), keyAgreement.generateKeyPair().getPublic())
            .setComponentsFromProtocolName("Noise_IK_25519_AESGCM_SHA256")
            .build();

    // We want to make sure we're testing the size of the resulting message (which may include key material and AEAD
    // tags) rather than the length of just the payload
    final int payloadLength = NoiseHandshake.MAX_NOISE_MESSAGE_SIZE - 1;
    final int messageLength = handshake.getOutboundMessageLength(payloadLength);

    assertTrue(messageLength > NoiseHandshake.MAX_NOISE_MESSAGE_SIZE);

    assertThrows(IllegalArgumentException.class,
        () -> handshake.writeMessage(new byte[payloadLength]));

    assertThrows(IllegalArgumentException.class,
        () -> handshake.writeMessage(new byte[payloadLength], 0, payloadLength, new byte[messageLength], 0));

    assertThrows(IllegalArgumentException.class,
        () -> handshake.writeMessage(ByteBuffer.allocate(payloadLength)));

    assertThrows(IllegalArgumentException.class,
        () -> handshake.writeMessage(ByteBuffer.allocate(payloadLength), ByteBuffer.allocate(messageLength)));
  }

  @Test
  void writeMessageShortBuffer() throws NoSuchAlgorithmException {
    final NoiseHandshake handshake =
        NoiseHandshakeBuilder.forNNInitiator()
            .setComponentsFromProtocolName("Noise_NN_25519_AESGCM_SHA256")
            .build();

    final byte[] payload = new byte[32];
    final byte[] message = new byte[payload.length - 1];

    assertThrows(ShortBufferException.class, () ->
        handshake.writeMessage(payload, 0, payload.length, message, 0));

    assertThrows(ShortBufferException.class, () ->
        handshake.writeMessage(ByteBuffer.wrap(payload), ByteBuffer.wrap(message)));
  }

  @Test
  void readMessageOversize() throws NoSuchAlgorithmException {
    final NoiseHandshake handshake =
        NoiseHandshakeBuilder.forNNResponder()
            .setComponentsFromProtocolName("Noise_NN_25519_AESGCM_SHA256")
            .build();

    final int messageLength = NoiseHandshake.MAX_NOISE_MESSAGE_SIZE + 1;

    assertThrows(IllegalArgumentException.class, () ->
        handshake.readMessage(new byte[messageLength]));

    assertThrows(IllegalArgumentException.class, () ->
        handshake.readMessage(new byte[messageLength], 0, messageLength, new byte[messageLength], 0));

    assertThrows(IllegalArgumentException.class, () ->
        handshake.readMessage(ByteBuffer.allocate(messageLength)));

    assertThrows(IllegalArgumentException.class, () ->
        handshake.readMessage(ByteBuffer.allocate(messageLength), ByteBuffer.allocate(messageLength)));
  }

  @Test
  void readMessageShortBuffer() throws NoSuchAlgorithmException {
    final NoiseHandshake handshake =
        NoiseHandshakeBuilder.forNNResponder()
            .setComponentsFromProtocolName("Noise_NN_25519_AESGCM_SHA256")
            .build();

    final byte[] message = new byte[128];
    final int payloadLength = handshake.getPayloadLength(message.length);

    assertThrows(ShortBufferException.class, () ->
        handshake.readMessage(message, 0, message.length, new byte[payloadLength - 1], 0));

    assertThrows(ShortBufferException.class, () ->
        handshake.readMessage(ByteBuffer.wrap(message), ByteBuffer.allocate(payloadLength - 1)));
  }
}
