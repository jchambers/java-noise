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

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class NoiseHandshakeTest {

  private static class HexDeserializer extends JsonDeserializer<byte[]> {

    @Override
    public byte[] deserialize(final JsonParser jsonParser, final DeserializationContext deserializationContext) throws IOException {
      return HexFormat.of().parseHex(jsonParser.getValueAsString());
    }
  }

  private record TestVector(
      String name,
      String pattern,

      @JsonProperty("dh")
      String keyAgreement,

      String cipher,
      String hash,

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
      byte[] ciphertext
  ) {}

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
  void completeHandshake(final TestVector testVector) {
    final HandshakePattern handshakePattern;

    try {
      handshakePattern = HandshakePattern.getInstance(testVector.pattern());
    } catch (final NoSuchPatternException e) {
      throw new TestAbortedException("Handshake pattern not supported: " + testVector.pattern());
    }

    final DefaultProtocolNameResolver resolver = new DefaultProtocolNameResolver();

    final NoiseKeyAgreement keyAgreement;

    try {
      keyAgreement = resolver.getKeyAgreement(testVector.keyAgreement());
    } catch (final NoSuchAlgorithmException e) {
      throw new TestAbortedException("Key agreement not supported: " + testVector.keyAgreement());
    }

    final NoiseCipher cipher;

    try {
      cipher = resolver.getCipher(testVector.cipher());
    } catch (final NoSuchAlgorithmException e) {
      throw new TestAbortedException("Cipher not supported: " + testVector.cipher());
    }

    final NoiseHash hash;

    try {
      hash = resolver.getHash(testVector.hash());
    } catch (final NoSuchAlgorithmException e) {
      throw new TestAbortedException("Hash not supported: " + testVector.hash());
    }

    new NoiseHandshake(NoiseHandshake.Role.INITIATOR,
        handshakePattern,
        keyAgreement,
        cipher,
        hash,
        null,
        null,
        null,
        null,
        null);

    new NoiseHandshake(NoiseHandshake.Role.RESPONDER,
        handshakePattern,
        keyAgreement,
        cipher,
        hash,
        null,
        null,
        null,
        null,
        null);
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
            return Arguments.of(Named.of(testVector.name(), testVector));
          } else {
            throw new RuntimeException("Unexpected object in stream: " + entry.getClass().getName());
          }
        });
  }
}