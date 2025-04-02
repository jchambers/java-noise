package com.eatthepath.noise;

import com.eatthepath.noise.component.NoiseKeyAgreement;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

class NoiseHandshakeTest {

  @Test
  void getOutboundMessageLength() throws NoSuchAlgorithmException {
    final NoiseHandshake noiseHandshake =
        NoiseHandshakeBuilder.forXXInitiator(NoiseKeyAgreement.getInstance("448").generateKeyPair())
            .setComponentsFromProtocolName("Noise_XX_448_AESGCM_SHA256")
            .build();

    // Expected lengths via https://noiseprotocol.org/noise.html#message-format
    assertEquals(56, noiseHandshake.getOutboundMessageLength(0, 0));
    assertEquals(144, noiseHandshake.getOutboundMessageLength(1, 0));
    assertEquals(88, noiseHandshake.getOutboundMessageLength(2, 0));

    assertEquals(59, noiseHandshake.getOutboundMessageLength(0, 3));
    assertEquals(149, noiseHandshake.getOutboundMessageLength(1, 5));
    assertEquals(95, noiseHandshake.getOutboundMessageLength(2, 7));
  }

  @Test
  void getPayloadLength() throws NoSuchAlgorithmException {
    final NoiseHandshake noiseHandshake =
        NoiseHandshakeBuilder.forXXInitiator(NoiseKeyAgreement.getInstance("448").generateKeyPair())
            .setComponentsFromProtocolName("Noise_XX_448_AESGCM_SHA256")
            .build();

    // Expected lengths via https://noiseprotocol.org/noise.html#message-format
    assertEquals(0, noiseHandshake.getPayloadLength(0, 56));
    assertEquals(0, noiseHandshake.getPayloadLength(1, 144));
    assertEquals(0, noiseHandshake.getPayloadLength(2, 88));

    assertEquals(3, noiseHandshake.getPayloadLength(0, 59));
    assertEquals(5, noiseHandshake.getPayloadLength(1, 149));
    assertEquals(7, noiseHandshake.getPayloadLength(2, 95));

    assertThrows(IllegalArgumentException.class,
        () -> noiseHandshake.getPayloadLength(0, 55));
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

  @Test
  void repeatedFallback() throws NoSuchAlgorithmException {
    final NoiseKeyAgreement keyAgreement = NoiseKeyAgreement.getInstance("25519");

    final KeyPair initiatorStaticKeyPair = keyAgreement.generateKeyPair();
    final PublicKey staleRemoteStaticPublicKey = keyAgreement.generateKeyPair().getPublic();
    final KeyPair currentResponderStaticKeyPair = keyAgreement.generateKeyPair();

    final byte[] initiatorStaticKeyMessage;
    {
      final NoiseHandshake ikInitiatorHandshake =
          NoiseHandshakeBuilder.forIKInitiator(initiatorStaticKeyPair, staleRemoteStaticPublicKey)
              .setComponentsFromProtocolName("Noise_IK_25519_AESGCM_SHA256")
              .build();

      initiatorStaticKeyMessage = ikInitiatorHandshake.writeMessage((byte[]) null);
    }

    final NoiseHandshake ikResponderHandshake =
        NoiseHandshakeBuilder.forIKResponder(currentResponderStaticKeyPair)
            .setComponentsFromProtocolName("Noise_IK_25519_AESGCM_SHA256")
            .build();

    assertThrows(AEADBadTagException.class, () -> ikResponderHandshake.readMessage(initiatorStaticKeyMessage));

    assertDoesNotThrow(() -> ikResponderHandshake.fallbackTo("XXfallback"));
    assertThrows(IllegalStateException.class, () -> ikResponderHandshake.fallbackTo("XXfallback"));

    assertFalse(ikResponderHandshake.isExpectingRead());
    assertFalse(ikResponderHandshake.isExpectingWrite());
    assertFalse(ikResponderHandshake.isDone());
  }
}
