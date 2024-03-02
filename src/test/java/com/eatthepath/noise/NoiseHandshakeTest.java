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
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
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

  @ParameterizedTest
  @MethodSource
  void cacophonyTests(final CacophonyTestVector testVector) throws InvalidKeySpecException, AEADBadTagException {
    final NoiseHandshakePair handshakePair = buildHandshakePair(testVector);

    if (handshakePair.initiatorHandshake().isOneWayHandshake()) {
      testOneWayHandshake(testVector, handshakePair);
    } else {
      testInteractiveHandshake(testVector, handshakePair);
    }
  }

  private void testOneWayHandshake(final CacophonyTestVector testVector, final NoiseHandshakePair handshakePair)
      throws InvalidKeySpecException, AEADBadTagException {

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

  private void testInteractiveHandshake(final CacophonyTestVector testVector, final NoiseHandshakePair handshakePair) throws AEADBadTagException, InvalidKeySpecException {
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

  private static Stream<Arguments> cacophonyTests() throws IOException {
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
  @MethodSource
  void fallbackTests(final NoiseCFallbackTestVector testVector) throws InvalidKeySpecException, AEADBadTagException, NoSuchPatternException {
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

  private static Stream<Arguments> fallbackTests() throws IOException {
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
