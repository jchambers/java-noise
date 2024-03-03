package com.eatthepath.noise;

import com.eatthepath.noise.component.NoiseKeyAgreement;
import com.eatthepath.noise.util.HexDeserializer;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.opentest4j.TestAbortedException;

import javax.annotation.Nullable;
import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.NamedParameterSpec;
import java.util.List;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.*;

class NoiseHandshakeTest {

  private record CacophonyTestVector(
      @JsonProperty("protocol_name")
      String protocolName,

      @JsonProperty("init_prologue")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] initiatorPrologue,

      @JsonProperty("init_ephemeral")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] initiatorEphemeralPrivateKey,

      @JsonProperty("init_static")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] initiatorStaticPrivateKey,

      @JsonProperty("init_remote_static")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] initiatorRemoteStaticPublicKey,

      @JsonProperty("init_psks")
      @JsonDeserialize(contentUsing = HexDeserializer.class)
      List<byte[]> initiatorPreSharedKeys,

      @JsonProperty("resp_prologue")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] responderPrologue,

      @JsonProperty("resp_ephemeral")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] responderEphemeralPrivateKey,

      @JsonProperty("resp_static")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] responderStaticPrivateKey,

      @JsonProperty("resp_remote_static")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] responderRemoteStaticPublicKey,

      @JsonProperty("resp_psks")
      @JsonDeserialize(contentUsing = HexDeserializer.class)
      List<byte[]> responderPreSharedKeys,

      @JsonProperty("handshake_hash")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] handshakeHash,

      List<TestMessage> messages) {
  }

  private record NoiseCFallbackTestVector(
      String name,

      @JsonProperty("pattern")
      String initialPattern,

      @JsonProperty("dh")
      String keyAgreement,

      String cipher,

      String hash,

      boolean fallback,

      @JsonProperty("init_prologue")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] initiatorPrologue,

      @JsonProperty("init_ephemeral")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] initiatorEphemeralPrivateKey,

      @JsonProperty("init_static")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] initiatorStaticPrivateKey,

      @JsonProperty("init_remote_static")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] initiatorRemoteStaticPublicKey,

      @JsonProperty("init_psks")
      @JsonDeserialize(contentUsing = HexDeserializer.class)
      List<byte[]> initiatorPreSharedKeys,

      @JsonProperty("resp_prologue")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] responderPrologue,

      @JsonProperty("resp_ephemeral")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] responderEphemeralPrivateKey,

      @JsonProperty("resp_static")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] responderStaticPrivateKey,

      @JsonProperty("resp_remote_static")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] responderRemoteStaticPublicKey,

      @JsonProperty("resp_psks")
      @JsonDeserialize(contentUsing = HexDeserializer.class)
      List<byte[]> responderPreSharedKeys,

      @JsonProperty("handshake_hash")
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] handshakeHash,

      List<TestMessage> messages) {
  }

  private record TestMessage(
      @JsonDeserialize(using = HexDeserializer.class)
      byte[] payload,

      @JsonDeserialize(using = HexDeserializer.class)
      byte[] ciphertext) {

  }

  private record NoiseHandshakePair(NoiseHandshake initiatorHandshake, NoiseHandshake responderHandshake) {
  }

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

  @ParameterizedTest
  @MethodSource("cacophonyTestVectors")
  void cacophonyTestsWithNewByteArray(final CacophonyTestVector testVector) throws AEADBadTagException {
    final NoiseHandshakePair handshakePair = buildHandshakePair(testVector);

    if (handshakePair.initiatorHandshake().isOneWayHandshake()) {
      testOneWayHandshakeWithNewByteArray(testVector, handshakePair);
    } else {
      testInteractiveHandshakeWithNewByteArray(testVector, handshakePair);
    }
  }

  private void testOneWayHandshakeWithNewByteArray(final CacophonyTestVector testVector, final NoiseHandshakePair handshakePair)
      throws AEADBadTagException {

    @Nullable NoiseTransportWriter transportWriter = null;
    @Nullable NoiseTransportReader transportReader = null;

    for (final TestMessage message : testVector.messages()) {
      if (transportWriter != null) {
        // We've finished the handshake and the test messages are now transport messages
        assertArrayEquals(message.ciphertext(), transportWriter.writeMessage(message.payload()));
        assertArrayEquals(message.payload(), transportReader.readMessage(message.ciphertext()));
      } else {
        // The handshake isn't done and more handshake messages are expected
        assertArrayEquals(message.ciphertext(), handshakePair.initiatorHandshake().writeMessage(message.payload()));
        assertArrayEquals(message.payload(), handshakePair.responderHandshake().readMessage(message.ciphertext()));
      }

      if (handshakePair.initiatorHandshake().isDone() && transportWriter == null) {
        transportWriter = handshakePair.initiatorHandshake().toTransportWriter();
        transportReader = handshakePair.responderHandshake().toTransportReader();
      }
    }
  }

  private void testInteractiveHandshakeWithNewByteArray(final CacophonyTestVector testVector, final NoiseHandshakePair handshakePair) throws AEADBadTagException {
    @Nullable NoiseTransport initiatorTransport = null;
    @Nullable NoiseTransport responderTransport = null;

    for (int i = 0; i < testVector.messages().size(); i++) {
      final TestMessage testMessage = testVector.messages().get(i);

      final NoiseHandshake senderHandshake =
          i % 2 == 0 ? handshakePair.initiatorHandshake() : handshakePair.responderHandshake();

      final NoiseHandshake receiverHandshake =
          i % 2 == 0 ? handshakePair.responderHandshake() : handshakePair.initiatorHandshake();

      @Nullable final NoiseTransport senderTransport = i % 2 == 0 ? initiatorTransport : responderTransport;
      @Nullable final NoiseTransport receiverTransport = i % 2 == 0 ? responderTransport : initiatorTransport;

      if (senderTransport != null && receiverTransport != null) {
        // This is a transport message, not a handshake message
        assertArrayEquals(testMessage.ciphertext(), senderTransport.writeMessage(testMessage.payload()));
        assertArrayEquals(testMessage.payload(), receiverTransport.readMessage(testMessage.ciphertext()));
      } else {
        assertTrue(senderHandshake.isExpectingWrite());
        assertTrue(receiverHandshake.isExpectingRead());

        assertArrayEquals(testMessage.ciphertext(), senderHandshake.writeMessage(testMessage.payload()));
        assertArrayEquals(testMessage.payload(), receiverHandshake.readMessage(testMessage.ciphertext()));
      }

      if (handshakePair.initiatorHandshake().isDone() && initiatorTransport == null) {
        assertTrue(handshakePair.responderHandshake().isDone());

        initiatorTransport = handshakePair.initiatorHandshake().toTransport();
        responderTransport = handshakePair.responderHandshake().toTransport();
      }
    }
  }

  @ParameterizedTest
  @MethodSource("cacophonyTestVectors")
  void cacophonyTestsWithNewByteBuffer(final CacophonyTestVector testVector) throws AEADBadTagException {
    final NoiseHandshakePair handshakePair = buildHandshakePair(testVector);

    if (handshakePair.initiatorHandshake().isOneWayHandshake()) {
      testOneWayHandshakeWithNewByteBuffer(testVector, handshakePair);
    } else {
      testInteractiveHandshakeWithNewByteBuffer(testVector, handshakePair);
    }
  }

  private void testOneWayHandshakeWithNewByteBuffer(final CacophonyTestVector testVector, final NoiseHandshakePair handshakePair)
      throws AEADBadTagException {

    @Nullable NoiseTransportWriter transportWriter = null;
    @Nullable NoiseTransportReader transportReader = null;

    for (final TestMessage message : testVector.messages()) {
      if (transportWriter != null) {
        // We've finished the handshake and the test messages are now transport messages
        assertEquals(ByteBuffer.wrap(message.ciphertext()), transportWriter.writeMessage(ByteBuffer.wrap(message.payload())));
        assertEquals(ByteBuffer.wrap(message.payload()), transportReader.readMessage(ByteBuffer.wrap(message.ciphertext())));
      } else {
        // The handshake isn't done and more handshake messages are expected
        assertEquals(ByteBuffer.wrap(message.ciphertext()), handshakePair.initiatorHandshake().writeMessage(ByteBuffer.wrap(message.payload())));
        assertEquals(ByteBuffer.wrap(message.payload()), handshakePair.responderHandshake().readMessage(ByteBuffer.wrap(message.ciphertext())));
      }

      if (handshakePair.initiatorHandshake().isDone() && transportWriter == null) {
        transportWriter = handshakePair.initiatorHandshake().toTransportWriter();
        transportReader = handshakePair.responderHandshake().toTransportReader();
      }
    }
  }

  private void testInteractiveHandshakeWithNewByteBuffer(final CacophonyTestVector testVector, final NoiseHandshakePair handshakePair) throws AEADBadTagException {
    @Nullable NoiseTransport initiatorTransport = null;
    @Nullable NoiseTransport responderTransport = null;

    for (int i = 0; i < testVector.messages().size(); i++) {
      final TestMessage testMessage = testVector.messages().get(i);

      final NoiseHandshake senderHandshake =
          i % 2 == 0 ? handshakePair.initiatorHandshake() : handshakePair.responderHandshake();

      final NoiseHandshake receiverHandshake =
          i % 2 == 0 ? handshakePair.responderHandshake() : handshakePair.initiatorHandshake();

      @Nullable final NoiseTransport senderTransport = i % 2 == 0 ? initiatorTransport : responderTransport;
      @Nullable final NoiseTransport receiverTransport = i % 2 == 0 ? responderTransport : initiatorTransport;

      if (senderTransport != null && receiverTransport != null) {
        // This is a transport message, not a handshake message
        assertEquals(ByteBuffer.wrap(testMessage.ciphertext()), senderTransport.writeMessage(ByteBuffer.wrap(testMessage.payload())));
        assertEquals(ByteBuffer.wrap(testMessage.payload()), receiverTransport.readMessage(ByteBuffer.wrap(testMessage.ciphertext())));
      } else {
        assertTrue(senderHandshake.isExpectingWrite());
        assertTrue(receiverHandshake.isExpectingRead());

        assertEquals(ByteBuffer.wrap(testMessage.ciphertext()), senderHandshake.writeMessage(ByteBuffer.wrap(testMessage.payload())));
        assertEquals(ByteBuffer.wrap(testMessage.payload()), receiverHandshake.readMessage(ByteBuffer.wrap(testMessage.ciphertext())));
      }

      if (handshakePair.initiatorHandshake().isDone() && initiatorTransport == null) {
        assertTrue(handshakePair.responderHandshake().isDone());

        initiatorTransport = handshakePair.initiatorHandshake().toTransport();
        responderTransport = handshakePair.responderHandshake().toTransport();
      }
    }
  }

  private static Stream<Arguments> cacophonyTestVectors() throws IOException {
    final InputStream testVectorInputStream = NoiseHandshakeTest.class.getResourceAsStream("cacophony-test-vectors.json");

    if (testVectorInputStream == null) {
      throw new IOException("Test vector file not found");
    }

    final ObjectReader objectReader = new ObjectMapper()
        .reader()
        .forType(CacophonyTestVector.class);

    return StreamSupport.stream(
            Spliterators.spliterator(objectReader.readValues(testVectorInputStream), 1,
                Spliterator.IMMUTABLE | Spliterator.NONNULL | Spliterator.ORDERED),
            false)
        .map(entry -> (CacophonyTestVector) entry)
        .map(testVector -> Arguments.of(Named.of(testVector.protocolName(), testVector)));
  }

  private static NoiseHandshakePair buildHandshakePair(final CacophonyTestVector testVector) {
    try {
      final NoiseHandshake initiatorHandshake;
      {
        final NamedProtocolHandshakeBuilder initiatorHandshakeBuilder =
            new NamedProtocolHandshakeBuilder(testVector.protocolName(), NoiseHandshake.Role.INITIATOR);

        if (testVector.initiatorStaticPrivateKey() != null) {
          initiatorHandshakeBuilder.setLocalStaticKeyPair(
              getXECKeyPairFromPrivateKey(testVector.initiatorStaticPrivateKey(), testVector.protocolName()));
        }

        if (testVector.initiatorEphemeralPrivateKey() != null) {
          initiatorHandshakeBuilder.setLocalEphemeralKeyPair(
              getXECKeyPairFromPrivateKey(testVector.initiatorEphemeralPrivateKey(), testVector.protocolName()));
        }

        if (testVector.initiatorRemoteStaticPublicKey() != null) {
          initiatorHandshakeBuilder.setRemoteStaticPublicKey(
              getXECPublicKey(testVector.initiatorRemoteStaticPublicKey(), testVector.protocolName()));
        }

        if (testVector.initiatorPreSharedKeys() != null) {
          initiatorHandshakeBuilder.setPreSharedKeys(testVector.initiatorPreSharedKeys());
        }

        initiatorHandshakeBuilder.setPrologue(testVector.initiatorPrologue());

        initiatorHandshake = initiatorHandshakeBuilder.build();
      }

      final NoiseHandshake responderHandshake;
      {
        final NamedProtocolHandshakeBuilder responderHandshakeBuilder =
            new NamedProtocolHandshakeBuilder(testVector.protocolName(), NoiseHandshake.Role.RESPONDER);

        if (testVector.responderStaticPrivateKey() != null) {
          responderHandshakeBuilder.setLocalStaticKeyPair(
              getXECKeyPairFromPrivateKey(testVector.responderStaticPrivateKey(), testVector.protocolName()));
        }

        if (testVector.responderEphemeralPrivateKey() != null) {
          responderHandshakeBuilder.setLocalEphemeralKeyPair(
              getXECKeyPairFromPrivateKey(testVector.responderEphemeralPrivateKey(), testVector.protocolName()));
        }

        if (testVector.responderRemoteStaticPublicKey() != null) {
          responderHandshakeBuilder.setRemoteStaticPublicKey(
              getXECPublicKey(testVector.responderRemoteStaticPublicKey(), testVector.protocolName()));
        }

        if (testVector.responderPreSharedKeys() != null) {
          responderHandshakeBuilder.setPreSharedKeys(testVector.responderPreSharedKeys());
        }

        responderHandshakeBuilder.setPrologue(testVector.responderPrologue());

        responderHandshake = responderHandshakeBuilder.build();
      }

      return new NoiseHandshakePair(initiatorHandshake, responderHandshake);
    } catch (final NoSuchAlgorithmException e) {
      throw new TestAbortedException("Unsupported algorithm: " + testVector.protocolName(), e);
    } catch (final NoSuchPatternException e) {
      throw new TestAbortedException("Unsupported handshake pattern: " + testVector.protocolName());
    }
  }

  @ParameterizedTest
  @MethodSource("fallbackTestVectors")
  void fallbackTestsWithNewByteArray(final NoiseCFallbackTestVector testVector) throws AEADBadTagException, NoSuchPatternException {
    Assumptions.assumeTrue(testVector.messages().size() >= 2,
        "Fallback test vectors must contain at least two messages");

    final NoiseHandshake ikInitiatorHandshake, ikResponderHandshake;
    {
      final NoiseHandshakePair ikHandshakePair = buildHandshakePair(testVector);

      ikInitiatorHandshake = ikHandshakePair.initiatorHandshake();
      ikResponderHandshake = ikHandshakePair.responderHandshake();
    }

    {
      final TestMessage ikMessage = testVector.messages().get(0);

      assertArrayEquals(ikMessage.ciphertext(), ikInitiatorHandshake.writeMessage(ikMessage.payload()));
      assertThrows(AEADBadTagException.class, () -> ikResponderHandshake.readMessage(ikMessage.ciphertext()));
    }

    final NoiseHandshake xxFallbackResponderHandshake = ikResponderHandshake.fallbackTo("XXfallback");
    assertTrue(xxFallbackResponderHandshake.isExpectingWrite());

    final NoiseHandshake xxFallbackInitiatorHandshake;
    {
      final TestMessage xxFallbackMessage = testVector.messages().get(1);

      assertArrayEquals(xxFallbackMessage.ciphertext(), xxFallbackResponderHandshake.writeMessage(xxFallbackMessage.payload()));
      assertThrows(AEADBadTagException.class, () -> ikInitiatorHandshake.readMessage(xxFallbackMessage.ciphertext()));

      xxFallbackInitiatorHandshake = ikInitiatorHandshake.fallbackTo("XXfallback");
      assertTrue(xxFallbackInitiatorHandshake.isExpectingRead());
      assertArrayEquals(xxFallbackMessage.payload(), xxFallbackInitiatorHandshake.readMessage(xxFallbackMessage.ciphertext()));
    }

    @Nullable NoiseTransport initiatorTransport = null;
    @Nullable NoiseTransport responderTransport = null;

    for (int i = 2; i < testVector.messages().size(); i++) {
      final TestMessage testMessage = testVector.messages().get(i);

      final NoiseHandshake senderHandshake =
          i % 2 == 0 ? xxFallbackInitiatorHandshake : xxFallbackResponderHandshake;

      final NoiseHandshake receiverHandshake =
          i % 2 == 0 ? xxFallbackResponderHandshake : xxFallbackInitiatorHandshake;

      @Nullable final NoiseTransport senderTransport = i % 2 == 0 ? initiatorTransport : responderTransport;
      @Nullable final NoiseTransport receiverTransport = i % 2 == 0 ? responderTransport : initiatorTransport;

      if (senderTransport != null && receiverTransport != null) {
        // This is a transport message, not a handshake message
        assertArrayEquals(testMessage.ciphertext(), senderTransport.writeMessage(testMessage.payload()));
        assertArrayEquals(testMessage.payload(), receiverTransport.readMessage(testMessage.ciphertext()));
      } else {
        assertTrue(senderHandshake.isExpectingWrite());
        assertTrue(receiverHandshake.isExpectingRead());

        assertArrayEquals(testMessage.ciphertext(), senderHandshake.writeMessage(testMessage.payload()));
        assertArrayEquals(testMessage.payload(), receiverHandshake.readMessage(testMessage.ciphertext()));
      }

      if (xxFallbackInitiatorHandshake.isDone() && initiatorTransport == null) {
        assertTrue(xxFallbackResponderHandshake.isDone());

        initiatorTransport = xxFallbackInitiatorHandshake.toTransport();
        responderTransport = xxFallbackResponderHandshake.toTransport();
      }
    }
  }

  @ParameterizedTest
  @MethodSource("fallbackTestVectors")
  void fallbackTestsWithNewByteBuffer(final NoiseCFallbackTestVector testVector) throws AEADBadTagException, NoSuchPatternException {
    Assumptions.assumeTrue(testVector.messages().size() >= 2,
        "Fallback test vectors must contain at least two messages");

    final NoiseHandshake ikInitiatorHandshake, ikResponderHandshake;
    {
      final NoiseHandshakePair ikHandshakePair = buildHandshakePair(testVector);

      ikInitiatorHandshake = ikHandshakePair.initiatorHandshake();
      ikResponderHandshake = ikHandshakePair.responderHandshake();
    }

    {
      final TestMessage ikMessage = testVector.messages().get(0);

      assertEquals(ByteBuffer.wrap(ikMessage.ciphertext()), ikInitiatorHandshake.writeMessage(ByteBuffer.wrap(ikMessage.payload())));
      assertThrows(AEADBadTagException.class, () -> ikResponderHandshake.readMessage(ByteBuffer.wrap(ikMessage.ciphertext())));
    }

    final NoiseHandshake xxFallbackResponderHandshake = ikResponderHandshake.fallbackTo("XXfallback");
    assertTrue(xxFallbackResponderHandshake.isExpectingWrite());

    final NoiseHandshake xxFallbackInitiatorHandshake;
    {
      final TestMessage xxFallbackMessage = testVector.messages().get(1);

      assertEquals(ByteBuffer.wrap(xxFallbackMessage.ciphertext()), xxFallbackResponderHandshake.writeMessage(ByteBuffer.wrap(xxFallbackMessage.payload())));
      assertThrows(AEADBadTagException.class, () -> ikInitiatorHandshake.readMessage(ByteBuffer.wrap(xxFallbackMessage.ciphertext())));

      xxFallbackInitiatorHandshake = ikInitiatorHandshake.fallbackTo("XXfallback");
      assertTrue(xxFallbackInitiatorHandshake.isExpectingRead());
      assertEquals(ByteBuffer.wrap(xxFallbackMessage.payload()), xxFallbackInitiatorHandshake.readMessage(ByteBuffer.wrap(xxFallbackMessage.ciphertext())));
    }

    @Nullable NoiseTransport initiatorTransport = null;
    @Nullable NoiseTransport responderTransport = null;

    for (int i = 2; i < testVector.messages().size(); i++) {
      final TestMessage testMessage = testVector.messages().get(i);

      final NoiseHandshake senderHandshake =
          i % 2 == 0 ? xxFallbackInitiatorHandshake : xxFallbackResponderHandshake;

      final NoiseHandshake receiverHandshake =
          i % 2 == 0 ? xxFallbackResponderHandshake : xxFallbackInitiatorHandshake;

      @Nullable final NoiseTransport senderTransport = i % 2 == 0 ? initiatorTransport : responderTransport;
      @Nullable final NoiseTransport receiverTransport = i % 2 == 0 ? responderTransport : initiatorTransport;

      if (senderTransport != null && receiverTransport != null) {
        // This is a transport message, not a handshake message
        assertEquals(ByteBuffer.wrap(testMessage.ciphertext()), senderTransport.writeMessage(ByteBuffer.wrap(testMessage.payload())));
        assertEquals(ByteBuffer.wrap(testMessage.payload()), receiverTransport.readMessage(ByteBuffer.wrap(testMessage.ciphertext())));
      } else {
        assertTrue(senderHandshake.isExpectingWrite());
        assertTrue(receiverHandshake.isExpectingRead());

        assertEquals(ByteBuffer.wrap(testMessage.ciphertext()), senderHandshake.writeMessage(ByteBuffer.wrap(testMessage.payload())));
        assertEquals(ByteBuffer.wrap(testMessage.payload()), receiverHandshake.readMessage(ByteBuffer.wrap(testMessage.ciphertext())));
      }

      if (xxFallbackInitiatorHandshake.isDone() && initiatorTransport == null) {
        assertTrue(xxFallbackResponderHandshake.isDone());

        initiatorTransport = xxFallbackInitiatorHandshake.toTransport();
        responderTransport = xxFallbackResponderHandshake.toTransport();
      }
    }
  }

  private static Stream<Arguments> fallbackTestVectors() throws IOException {
    final InputStream testVectorInputStream = NoiseHandshakeTest.class.getResourceAsStream("noise-c-fallback-test-vectors.json");

    if (testVectorInputStream == null) {
      throw new IOException("Test vector file not found");
    }

    final ObjectReader objectReader = new ObjectMapper()
        .reader()
        .forType(NoiseCFallbackTestVector.class);

    return StreamSupport.stream(
            Spliterators.spliterator(objectReader.readValues(testVectorInputStream), 1,
                Spliterator.IMMUTABLE | Spliterator.NONNULL | Spliterator.ORDERED),
            false)
        .map(entry -> (NoiseCFallbackTestVector) entry)
        .map(testVector -> Arguments.of(Named.of(testVector.name(), testVector)));
  }

  private NoiseHandshakePair buildHandshakePair(NoiseCFallbackTestVector testVector) {
    final String initialProtocolName = String.join("_", "Noise",
        testVector.initialPattern(),
        testVector.keyAgreement(),
        testVector.cipher(),
        testVector.hash());

    try {
      final NoiseHandshake initiatorHandshake;
      {
        final NamedProtocolHandshakeBuilder initiatorHandshakeBuilder =
            new NamedProtocolHandshakeBuilder(initialProtocolName, NoiseHandshake.Role.INITIATOR);

        if (testVector.initiatorStaticPrivateKey() != null) {
          initiatorHandshakeBuilder.setLocalStaticKeyPair(
              getXECKeyPairFromPrivateKey(testVector.initiatorStaticPrivateKey(), initialProtocolName));
        }

        if (testVector.initiatorEphemeralPrivateKey() != null) {
          initiatorHandshakeBuilder.setLocalEphemeralKeyPair(
              getXECKeyPairFromPrivateKey(testVector.initiatorEphemeralPrivateKey(), initialProtocolName));
        }

        if (testVector.initiatorRemoteStaticPublicKey() != null) {
          initiatorHandshakeBuilder.setRemoteStaticPublicKey(
              getXECPublicKey(testVector.initiatorRemoteStaticPublicKey(), initialProtocolName));
        }

        if (testVector.initiatorPreSharedKeys() != null) {
          initiatorHandshakeBuilder.setPreSharedKeys(testVector.initiatorPreSharedKeys());
        }

        initiatorHandshakeBuilder.setPrologue(testVector.initiatorPrologue());

        initiatorHandshake = initiatorHandshakeBuilder.build();
      }

      final NoiseHandshake responderHandshake;
      {
        final NamedProtocolHandshakeBuilder responderHandshakeBuilder =
            new NamedProtocolHandshakeBuilder(initialProtocolName, NoiseHandshake.Role.RESPONDER);

        if (testVector.responderStaticPrivateKey() != null) {
          responderHandshakeBuilder.setLocalStaticKeyPair(
              getXECKeyPairFromPrivateKey(testVector.responderStaticPrivateKey(), initialProtocolName));
        }

        if (testVector.responderEphemeralPrivateKey() != null) {
          responderHandshakeBuilder.setLocalEphemeralKeyPair(
              getXECKeyPairFromPrivateKey(testVector.responderEphemeralPrivateKey(), initialProtocolName));
        }

        if (testVector.responderRemoteStaticPublicKey() != null) {
          responderHandshakeBuilder.setRemoteStaticPublicKey(
              getXECPublicKey(testVector.responderRemoteStaticPublicKey(), initialProtocolName));
        }

        if (testVector.responderPreSharedKeys() != null) {
          responderHandshakeBuilder.setPreSharedKeys(testVector.responderPreSharedKeys());
        }

        responderHandshakeBuilder.setPrologue(testVector.responderPrologue());

        responderHandshake = responderHandshakeBuilder.build();
      }

      return new NoiseHandshakePair(initiatorHandshake, responderHandshake);
    } catch (final NoSuchAlgorithmException e) {
      throw new TestAbortedException("Unsupported algorithm: " + initialProtocolName, e);
    } catch (final NoSuchPatternException e) {
      throw new TestAbortedException("Unsupported handshake pattern: " + initialProtocolName);
    }
  }

  private static PublicKey getXECPublicKey(final byte[] publicKeyBytes, final String noiseProtocolName) {
    try {
      final String keyAgreementName = noiseProtocolName.split("_")[2];
      final NoiseKeyAgreement noiseKeyAgreement = NoiseKeyAgreement.getInstance(keyAgreementName);

      return noiseKeyAgreement.deserializePublicKey(publicKeyBytes);
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private static KeyPair getXECKeyPairFromPrivateKey(final byte[] privateKeyBytes, final String noiseProtocolName) {
    // TODO This whole thing is a reeeeeeeeal ugly hack and really ought to get replaced
    final String keyAgreementAlgorithm;
    {
      final String keyAgreementName = noiseProtocolName.split("_")[2];

      keyAgreementAlgorithm = switch (keyAgreementName) {
        case "25519" -> "X25519";
        case "448" -> "X448";
        default -> throw new IllegalArgumentException("Unexpected key agreement name: " + keyAgreementName);
      };
    }

    try {
      // Via https://stackoverflow.com/questions/58583774/how-to-generate-publickey-for-privatekey-in-x25519
      final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAgreementAlgorithm);

      keyPairGenerator.initialize(new NamedParameterSpec(keyAgreementAlgorithm), new SecureRandom() {
        @Override
        public void nextBytes(final byte[] bytes) {
          System.arraycopy(privateKeyBytes, 0, bytes, 0, bytes.length);
        }
      });

      return keyPairGenerator.generateKeyPair();
    } catch (final InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
