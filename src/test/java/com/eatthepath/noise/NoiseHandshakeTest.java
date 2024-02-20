package com.eatthepath.noise;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
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
import java.util.*;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.*;

class NoiseHandshakeTest {

  private static class HexDeserializer extends JsonDeserializer<byte[]> {

    @Override
    public byte[] deserialize(final JsonParser jsonParser, final DeserializationContext deserializationContext) throws IOException {
      return HexFormat.of().parseHex(jsonParser.getValueAsString());
    }
  }

  private record TestVector(
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
  void completeHandshake(final TestVector testVector) throws InvalidKeySpecException, AEADBadTagException {
    final NoiseHandshakePair handshakePair = buildHandshakePair(testVector);

    @Nullable NoiseMessageReaderWriterPair initiatorReaderWriterPair = null;
    @Nullable NoiseMessageReaderWriterPair responderReaderWriterPair = null;

    for (int i = 0; i < testVector.messages().size(); i++) {
      final TestMessage testMessage = testVector.messages().get(i);

      if (i % 2 == 0) {
        // It's the initiator's turn to send a message to the responder
        if (initiatorReaderWriterPair != null) {
          // This is a transport message, not a handshake message
          assertArrayEquals(testMessage.ciphertext(), initiatorReaderWriterPair.noiseMessageWriter().writeMessage(testMessage.payload()));
          assertArrayEquals(testMessage.payload(), responderReaderWriterPair.noiseMessageReader().readMessage(testMessage.ciphertext()));
        } else {
          // We're still passing handshake messages back and forth
          assertTrue(handshakePair.initiatorHandshake().expectingWrite());
          assertTrue(handshakePair.responderHandshake().expectingRead());

          assertArrayEquals(testMessage.ciphertext(), handshakePair.initiatorHandshake().writeMessage(testMessage.payload()));
          assertArrayEquals(testMessage.payload(), handshakePair.responderHandshake().readMessage(testMessage.ciphertext()));
        }
      } else {
        // It's the responder's turn to send a message to the initiator
        if (initiatorReaderWriterPair != null) {
          // This is a transport message, not a handshake message
          assertArrayEquals(testMessage.ciphertext(), responderReaderWriterPair.noiseMessageWriter().writeMessage(testMessage.payload()));
          assertArrayEquals(testMessage.payload(), initiatorReaderWriterPair.noiseMessageReader().readMessage(testMessage.ciphertext()));
        } else {
          // We're still passing handshake messages back and forth
          assertTrue(handshakePair.responderHandshake().expectingWrite());
          assertTrue(handshakePair.initiatorHandshake().expectingRead());

          assertArrayEquals(testMessage.ciphertext(), handshakePair.responderHandshake().writeMessage(testMessage.payload()));
          assertArrayEquals(testMessage.payload(), handshakePair.initiatorHandshake().readMessage(testMessage.ciphertext()));
        }
      }

      if (handshakePair.initiatorHandshake().isDone() && initiatorReaderWriterPair == null) {
        assertTrue(handshakePair.initiatorHandshake().isDone());

        initiatorReaderWriterPair = handshakePair.initiatorHandshake().split();
        responderReaderWriterPair = handshakePair.responderHandshake().split();
      }
    }
  }

  private static Stream<Arguments> completeHandshake() throws IOException {
    final InputStream testVectorInputStream = NoiseHandshakeTest.class.getResourceAsStream("test-vectors.json");

    if (testVectorInputStream == null) {
      throw new IOException("Test vector file not found");
    }

    final ObjectReader objectReader = new ObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
        .reader()
        .forType(TestVector.class);

    return StreamSupport.stream(
            Spliterators.spliterator(objectReader.readValues(testVectorInputStream), 1,
                Spliterator.IMMUTABLE | Spliterator.NONNULL | Spliterator.ORDERED),
            false)
        .map(entry -> {
          if (entry instanceof TestVector testVector) {
            return Arguments.of(Named.of(testVector.protocolName(), testVector));
          } else {
            throw new RuntimeException("Unexpected object in stream: " + entry.getClass().getName());
          }
        });
  }

  private static NoiseHandshakePair buildHandshakePair(final TestVector testVector) {
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

  private static PublicKey getXECPublicKey(final byte[] publicKeyBytes, final String noiseProtocolName) {
    try {
      final String keyAgreementName = noiseProtocolName.split("_")[2];
      final NoiseKeyAgreement noiseKeyAgreement = new DefaultProtocolNameResolver().getKeyAgreement(keyAgreementName);

      return noiseKeyAgreement.deserializePublicKey(publicKeyBytes);
    } catch (final NoSuchAlgorithmException | InvalidKeySpecException e) {
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
