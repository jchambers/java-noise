package com.eatthepath.noise;

import com.eatthepath.noise.component.NoiseCipher;
import com.eatthepath.noise.component.NoiseHash;
import com.eatthepath.noise.component.NoiseKeyAgreement;

import javax.annotation.Nullable;
import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * A {@code NoiseHandshake} instance is responsible for encrypting and decrypting the messages that comprise a Noise
 * handshake. Once a Noise handshake instance has finished exchanging handshake messages, it can produce a Noise
 * transport object for steady-state encryption and decryption of Noise transport messages.
 * <p>
 * Noise handshake messages contain key material and an optional payload. The security properties for the optional
 * payload vary by handshake pattern, message, and sender role. Callers are responsible for verifying that the security
 * properties associated with ny handshake message are suitable for their use case. Please see
 * <a href="https://noiseprotocol.org/noise.html#payload-security-properties">The Noise Protocol Framework - Payload
 * security properties</a> for a complete explanation.
 * <p>
 * Generally speaking, the initiator and responder alternate sending and receiving messages until all messages in the
 * handshake pattern have been exchanged. At that point, callers transform (or "split" in the terminology of the Noise
 * Protocol Framework specification) the Noise handshake into a Noise transport instance appropriate for the handshake
 * type (i.e. one-way or bidirectional) and pass Noise transport messages between the initiator and responder as needed.
 *
 * <h2>Fallback patterns</h2>
 *
 * Noise handshakes can "fall back" to another pattern to handle certain kinds of errors. As an example, the
 * <a href="https://noiseprotocol.org/noise.html#noise-pipes">Noise Pipes</a> compound protocol expects that initiators
 * will usually have the responder's static public key available from a previous "full" (XX) handshake, and can use an
 * abbreviated (IK) handshake pattern with that static key set via a pre-handshake message. If the responder can't
 * decrypt a message from the initiator, though, it might conclude that the initiator has a stale copy of its public key
 * and can fall back to a "full" (XXfallback) handshake.
 *
 * <p>The IK handshake pattern is defined as:</p>
 *
 * <pre>IK:
 *   &lt;- s
 *   ...
 *   -&gt; e, es, s, ss
 *   &lt;- e, ee, se</pre>
 *
 * <p>…and the XXfallback pattern is defined as:</p>
 *
 * <pre>XXfallback:
 *   -&gt; e
 *   ...
 *   &lt;- e, ee, s, es
 *   -&gt; s, se</pre>
 *
 * <p>As an example, consider a scenario where the initiator of an IK handshake has a "stale" static key for the
 * responder:</p>
 *
 * {@snippet file="NoiseHandshakeExample.java" region="build-ik-handshake"}
 *
 * <p>The initiator sends its first message to the responder, which won't be able to decrypt the message due to the
 * static key disagreement:</p>
 *
 * {@snippet file="NoiseHandshakeExample.java" region="send-initiator-static-key-message"}
 *
 * <p>Rather than simply failing the handshake (assuming both the initiator and responder are expecting that a fallback
 * may happen), the responder can fall back to the XXfallback pattern, reusing the ephemeral key it already received
 * from the initiator as a pre-handshake message, and write a message to continue the XXfallback pattern:</p>
 *
 * {@snippet file="NoiseHandshakeExample.java" region="responder-fallback"}
 *
 * <p>The initiator will fail to decrypt the message from the responder:</p>
 *
 * {@snippet file="NoiseHandshakeExample.java" region="initiator-read-fallback-message"}
 *
 * <p>Like the responder, the initiator can take the decryption failure as a cue to fall back to the XXfallback pattern,
 * then read the message and finish the handshake:</p>
 *
 * {@snippet file="NoiseHandshakeExample.java" region="initiator-fallback"}
 *
 * <p>Once the handshake is finished, the transition to the transport phase of the protocol continues as usual.</p>
 *
 * @see NamedProtocolHandshakeBuilder
 * @see NoiseHandshakeBuilder
 *
 * @see <a href="https://noiseprotocol.org/noise.html#payload-security-properties">The Noise Protocol Framework - Payload security proprties</a>
 */
public class NoiseHandshake {

  private final String noiseProtocolName;
  private final HandshakePattern handshakePattern;
  private final Role role;

  private int currentMessagePattern = 0;
  private boolean hasSplit = false;

  private final CipherState cipherState;
  private final NoiseHash noiseHash;
  private final NoiseKeyAgreement keyAgreement;

  private final byte[] chainingKey;
  private final byte[] hash;

  private final byte[] prologue;

  @Nullable
  private KeyPair localEphemeralKeyPair;

  @Nullable
  private PublicKey remoteEphemeralPublicKey;

  @Nullable
  private final KeyPair localStaticKeyPair;

  @Nullable
  private PublicKey remoteStaticPublicKey;

  @Nullable
  private final List<byte[]> preSharedKeys;

  private int currentPreSharedKey;

  private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

  /**
   * An enumeration of roles within a Noise handshake.
   */
  public enum Role {
    /**
     * Indicates that a party is the initiator of a Noise handshake.
     */
    INITIATOR,

    /**
     * Indicates that a party is the responder in a Noise handshake.
     */
    RESPONDER
  }

  NoiseHandshake(final Role role,
                 final HandshakePattern handshakePattern,
                 final NoiseKeyAgreement keyAgreement,
                 final NoiseCipher noiseCipher,
                 final NoiseHash noiseHash,
                 @Nullable final byte[] prologue,
                 @Nullable final KeyPair localStaticKeyPair,
                 @Nullable final KeyPair localEphemeralKeyPair,
                 @Nullable final PublicKey remoteStaticPublicKey,
                 @Nullable final PublicKey remoteEphemeralPublicKey,
                 @Nullable final List<byte[]> preSharedKeys) {

    this.handshakePattern = handshakePattern;
    this.role = role;

    this.cipherState = new CipherState(noiseCipher);
    this.noiseHash = noiseHash;
    this.keyAgreement = keyAgreement;

    if (handshakePattern.requiresLocalStaticKeyPair(role)) {
      if (localStaticKeyPair == null) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern requires a local static key pair for " + role + " role");
      }
    } else {
      if (localStaticKeyPair != null) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern does not allow a local static key pair for " + role + " role");
      }
    }

    if (handshakePattern.requiresRemoteStaticPublicKey(role)) {
      if (remoteStaticPublicKey == null) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern requires a remote static public key for " + role + " role");
      }
    } else {
      if (remoteStaticPublicKey != null) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern does not allow a remote static public key for " + role + " role");
      }
    }

    final int requiredPreSharedKeys = handshakePattern.getRequiredPreSharedKeyCount();

    if (requiredPreSharedKeys > 0) {
      if (preSharedKeys == null || preSharedKeys.size() != requiredPreSharedKeys) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern requires " + requiredPreSharedKeys + " pre-shared keys");
      }

      if (preSharedKeys.stream().anyMatch(preSharedKey -> preSharedKey.length != 32)) {
        throw new IllegalArgumentException("Pre-shared keys must be exactly 32 bytes");
      }
    } else {
      if (preSharedKeys != null && !preSharedKeys.isEmpty()) {
        throw new IllegalArgumentException(handshakePattern.getName() + " handshake pattern does not allow pre-shared keys");
      }
    }

    this.prologue = prologue;

    // TODO Validate key compatibility
    this.localStaticKeyPair = localStaticKeyPair;
    this.localEphemeralKeyPair = localEphemeralKeyPair;
    this.remoteStaticPublicKey = remoteStaticPublicKey;
    this.remoteEphemeralPublicKey = remoteEphemeralPublicKey;
    this.preSharedKeys = preSharedKeys;

    this.noiseProtocolName = "Noise_" +
        handshakePattern.getName() + "_" +
        keyAgreement.getName() + "_" +
        noiseCipher.getName() + "_" +
        noiseHash.getName();

    hash = new byte[noiseHash.getHashLength()];

    final byte[] protocolNameBytes = noiseProtocolName.getBytes(StandardCharsets.UTF_8);

    final MessageDigest messageDigest = noiseHash.getMessageDigest();

    if (protocolNameBytes.length <= messageDigest.getDigestLength()) {
      System.arraycopy(protocolNameBytes, 0, hash, 0, protocolNameBytes.length);
    } else {
      try {
        messageDigest.reset();
        messageDigest.update(protocolNameBytes);
        messageDigest.digest(hash, 0, hash.length);
      } catch (final DigestException e) {
        // This should never happen
        throw new AssertionError(e);
      }
    }

    chainingKey = hash.clone();
    mixHash(prologue != null ? prologue : EMPTY_BYTE_ARRAY);

    Arrays.stream(handshakePattern.getPreMessagePatterns())
        // Process the initiator's keys first; "initiator" comes before "responder" in the `Role` enum, and so we don't
        // need a specialized comparator
        .sorted(Comparator.comparing(HandshakePattern.MessagePattern::sender))
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens())
            .map(token -> switch (token) {
              case E -> {
                final PublicKey ephemeralPublicKey;

                if (messagePattern.sender() == role) {
                  ephemeralPublicKey = localEphemeralKeyPair != null ? localEphemeralKeyPair.getPublic() : null;
                } else {
                  ephemeralPublicKey = remoteEphemeralPublicKey;
                }

                if (ephemeralPublicKey == null) {
                  throw new IllegalStateException("Ephemeral public key for " + messagePattern.sender() + " role must not be null");
                }

                yield ephemeralPublicKey;
              }
              case S -> {
                final PublicKey staticPublicKey;

                if (messagePattern.sender() == role) {
                  staticPublicKey = localStaticKeyPair != null ? localStaticKeyPair.getPublic() : null;
                } else {
                  staticPublicKey = remoteStaticPublicKey;
                }

                if (staticPublicKey == null) {
                  throw new IllegalStateException("Static public key for " + messagePattern.sender() + " role must not be null");
                }

                yield staticPublicKey;
              }
              case EE, ES, SE, SS, PSK ->
                  throw new IllegalArgumentException("Key-mixing tokens must not appear in pre-messages");
            }))
        .forEach(publicKey -> mixHash(keyAgreement.serializePublicKey(publicKey)));
  }

  /**
   * Returns the full name of the Noise protocol for this handshake.
   *
   * @return the full name of the Noise protocol for this handshake
   *
   * @see <a href="https://noiseprotocol.org/noise.html#protocol-names-and-modifiers">The Noise Protocol Framework - Protocol names and modifiers</a>
   */
  public String getNoiseProtocolName() {
    return noiseProtocolName;
  }

  private void mixKey(final byte[] inputKeyMaterial) {
    final byte[][] derivedKeys = noiseHash.deriveKeys(chainingKey, inputKeyMaterial, 2);

    System.arraycopy(derivedKeys[0], 0, chainingKey, 0, derivedKeys[0].length);
    cipherState.setKey(derivedKeys[1]);
  }

  private void mixHash(final byte[] bytes) {
    mixHash(bytes, 0, bytes.length);
  }

  private void mixHash(final byte[] bytes, final int offset, final int length) {
    final MessageDigest messageDigest = noiseHash.getMessageDigest();

    try {
      messageDigest.reset();
      messageDigest.update(hash);
      messageDigest.update(bytes, offset, length);
      messageDigest.digest(hash, 0, hash.length);
    } catch (final DigestException e) {
      // This should never happen
      throw new AssertionError(e);
    }
  }

  private void mixKeyAndHash(final byte[] preSharedKey) {
    final byte[][] derivedKeys = noiseHash.deriveKeys(chainingKey, preSharedKey, 3);

    System.arraycopy(derivedKeys[0], 0, chainingKey, 0, derivedKeys[0].length);
    mixHash(derivedKeys[1]);
    cipherState.setKey(derivedKeys[2]);
  }

  private int encryptAndHash(final byte[] plaintext,
                             final int plaintextOffset,
                             final int plaintextLength,
                             final byte[] ciphertext,
                             final int ciphertextOffset) throws ShortBufferException {

    final int ciphertextLength =
        cipherState.encrypt(hash, 0, hash.length, plaintext, plaintextOffset, plaintextLength, ciphertext, ciphertextOffset);

    mixHash(ciphertext, ciphertextOffset, ciphertextLength);

    return ciphertextLength;
  }

  private int decryptAndHash(final byte[] ciphertext,
                             final int ciphertextOffset,
                             final int ciphertextLength,
                             final byte[] plaintext,
                             final int plaintextOffset) throws ShortBufferException, AEADBadTagException {

    final int plaintextLength =
        cipherState.decrypt(hash, 0, hash.length, ciphertext, ciphertextOffset, ciphertextLength, plaintext, plaintextOffset);

    mixHash(ciphertext, ciphertextOffset, ciphertextLength);

    return plaintextLength;
  }

  /**
   * Checks whether this is a handshake for a one-way Noise handshake pattern.
   *
   * @return {@code true} if this is a handshake for a one-way Noise handshake pattern or {@code false} if this is a
   * handshake for a bidirectional Noise handshake pattern
   */
  public boolean isOneWayHandshake() {
    return handshakePattern.isOneWayPattern();
  }

  /**
   * Checks if this handshake is currently expecting to receive a handshake message from its peer.
   *
   * @return {@code true} if this handshake is expecting to receive a handshake message from its peer as its next action
   * or {@code false} if this handshake is done or is expecting to send a handshake message to its peer as its next
   * action
   *
   * @see #isExpectingWrite()
   * @see #isDone()
   */
  public boolean isExpectingRead() {
    if (currentMessagePattern < handshakePattern.getHandshakeMessagePatterns().length) {
      return handshakePattern.getHandshakeMessagePatterns()[currentMessagePattern].sender() != role;
    }

    // We've completed the whole handshake, so we're not expecting any more messages
    return false;
  }

  /**
   * Checks if this handshake is currently expecting to send a handshake message to its peer.
   *
   * @return {@code true} if this handshake is expecting to send a handshake message to its peer as its next action or
   * {@code false} if this handshake is done or is expecting to receive a handshake message from its peer as its next
   * action
   *
   * @see #isExpectingRead()
   * @see #isDone()
   */
  public boolean isExpectingWrite() {
    if (currentMessagePattern < handshakePattern.getHandshakeMessagePatterns().length) {
      return handshakePattern.getHandshakeMessagePatterns()[currentMessagePattern].sender() == role;
    }

    // We've completed the whole handshake, so we're not expecting any more messages
    return false;
  }

  /**
   * Checks if this handshake has successfully exchanged all messages required by its handshake pattern.
   *
   * @return {@code true} if all required messages have been exchanged or {@code false} if more exchanges are required
   *
   * @see #isExpectingRead()
   * @see #isExpectingWrite()
   */
  public boolean isDone() {
    return currentMessagePattern == handshakePattern.getHandshakeMessagePatterns().length;
  }

  /**
   * Returns the length of the Noise handshake message this handshake would produce for a payload with the given length
   * and with this handshake's current state.
   *
   * @param payloadLength the length of a payload's plaintext
   *
   * @return the length of the message this handshake would produce for a payload with the given length
   *
   * @throws IllegalStateException if this handshake is not currently expecting to send a message to its peer
   */
  public int getOutboundMessageLength(final int payloadLength) {
    if (!isExpectingWrite()) {
      throw new IllegalArgumentException("Handshake is not currently expecting to send a message");
    }

    return getOutboundMessageLength(handshakePattern, currentMessagePattern, keyAgreement.getPublicKeyLength(), payloadLength);
  }

  // Visible for testing
  static int getOutboundMessageLength(final HandshakePattern handshakePattern,
                                      final int message,
                                      final int publicKeyLength,
                                      final int payloadLength) {

    if (message < 0 || message >= handshakePattern.getHandshakeMessagePatterns().length) {
      throw new IndexOutOfBoundsException(
          String.format("Message index must be between 0 and %d for this handshake pattern, but was %d",
              handshakePattern.getHandshakeMessagePatterns().length, message));
    }

    final boolean isPreSharedKeyHandshake = handshakePattern.isPreSharedKeyHandshake();

    // Run through all of this handshake's message patterns to see if we have a key prior to reaching the message of
    // interest
    boolean hasKey = Arrays.stream(handshakePattern.getHandshakeMessagePatterns())
        .limit(message)
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == HandshakePattern.Token.EE
            || token == HandshakePattern.Token.ES
            || token == HandshakePattern.Token.SE
            || token == HandshakePattern.Token.SS
            || token == HandshakePattern.Token.PSK
            || (token == HandshakePattern.Token.E && isPreSharedKeyHandshake));

    int messageLength = 0;

    for (final HandshakePattern.Token token : handshakePattern.getHandshakeMessagePatterns()[message].tokens()) {
      switch (token) {
        case E -> {
          messageLength += publicKeyLength;

          if (isPreSharedKeyHandshake) {
            hasKey = true;
          }
        }
        case S -> {
          messageLength += publicKeyLength;

          if (hasKey) {
            // If we have a key, then the static key is encrypted and has a 16-byte AEAD tag
            messageLength += 16;
          }
        }
        case EE, ES, SE, SS, PSK -> hasKey = true;
      }
    }

    messageLength += payloadLength;

    if (hasKey) {
      // If we have a key, then the payload is encrypted and has a 16-byte AEAD tag
      messageLength += 16;
    }

    return messageLength;
  }

  /**
   * Returns the length of the plaintext of a payload contained in a Noise handshake message of the given length and
   * with this handshake's current state.
   *
   * @param handshakeMessageLength the length of a Noise handshake message received from this party's peer
   *
   * @return the length of the plaintext of a payload contained in a handshake message of the given length
   *
   * @throws IllegalStateException if this handshake is not currently expecting to receive a message from its peer
   * @throws IllegalArgumentException if the given handshake message length shorter than the minimum expected length of
   * an incoming handshake message
   */
  public int getPayloadLength(final int handshakeMessageLength) {
    if (!isExpectingRead()) {
      throw new IllegalStateException("Handshake is not currently expecting to read a message");
    }

    return getPayloadLength(handshakePattern, currentMessagePattern, keyAgreement.getPublicKeyLength(), handshakeMessageLength);
  }

  static int getPayloadLength(final HandshakePattern handshakePattern,
                              final int message,
                              final int publicKeyLength,
                              final int ciphertextLength) {

    final int emptyPayloadMessageLength = getOutboundMessageLength(handshakePattern, message, publicKeyLength, 0);

    if (ciphertextLength < emptyPayloadMessageLength) {
      throw new IllegalArgumentException("Ciphertext is shorter than minimum expected message length");
    }

    return ciphertextLength - emptyPayloadMessageLength;
  }

  public byte[] writeMessage(@Nullable final byte[] payload) {
    // TODO Verify that message size is within bounds
    final int payloadLength = payload != null ? payload.length : 0;
    final byte[] message = new byte[getOutboundMessageLength(payloadLength)];

    try {
      final int messageLength = writeMessage(message, 0, payload, 0, payloadLength);
      assert message.length == messageLength;
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return message;
  }

  public int writeMessage(final byte[] message,
                          final int messageOffset,
                          @Nullable final byte[] payload,
                          final int payloadOffset,
                          final int payloadLength) throws ShortBufferException {

    // TODO Check message buffer length, or just let plumbing deeper down complain?

    if (!isExpectingWrite()) {
      throw new IllegalStateException("Handshake not currently expecting to write a message");
    }

    int offset = messageOffset;

    final HandshakePattern.MessagePattern messagePattern =
        handshakePattern.getHandshakeMessagePatterns()[currentMessagePattern];

    for (final HandshakePattern.Token token : messagePattern.tokens()) {
      switch (token) {
        case E -> {
          // Ephemeral keys may be specified in advance for "fallback" patterns and for testing, and so may not
          // necessarily be null at this point.
          if (localEphemeralKeyPair == null) {
            localEphemeralKeyPair = keyAgreement.generateKeyPair();
          }

          final byte[] ephemeralKeyBytes = keyAgreement.serializePublicKey(localEphemeralKeyPair.getPublic());
          System.arraycopy(ephemeralKeyBytes, 0, message, offset, keyAgreement.getPublicKeyLength());

          mixHash(ephemeralKeyBytes);

          if (handshakePattern.isPreSharedKeyHandshake()) {
            mixKey(ephemeralKeyBytes);
          }

          offset += keyAgreement.getPublicKeyLength();
        }

        case S -> {
          if (localStaticKeyPair == null) {
            throw new IllegalStateException("No local static public key available");
          }

          try {
            offset += encryptAndHash(keyAgreement.serializePublicKey(localStaticKeyPair.getPublic()), 0, keyAgreement.getPublicKeyLength(),
                message, offset);
          } catch (final ShortBufferException e) {
            // This should never happen for buffers we control
            throw new AssertionError("Short buffer for static key component", e);
          }
        }

        case EE, ES, SE, SS, PSK -> handleMixKeyToken(token);
      }
    }

    if (payload != null) {
      offset += encryptAndHash(payload, payloadOffset, payloadLength, message, offset);
    } else {
      offset += encryptAndHash(EMPTY_BYTE_ARRAY, 0, 0, message, offset);
    }

    currentMessagePattern += 1;

    return offset;
  }

  public byte[] readMessage(final byte[] message) throws InvalidKeySpecException, AEADBadTagException {
    final byte[] payload = new byte[getPayloadLength(message.length)];

    try {
      final int payloadLength = readMessage(message, 0, message.length, payload, 0);
      assert payload.length == payloadLength;
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return payload;
  }

  public int readMessage(final byte[] message,
                         final int messageOffset,
                         final int messageLength,
                         final byte[] payload,
                         final int payloadOffset) throws InvalidKeySpecException, ShortBufferException, AEADBadTagException {

    if (!isExpectingRead()) {
      throw new IllegalStateException("Handshake not currently expecting to read a message");
    }

    int offset = messageOffset;

    final HandshakePattern.MessagePattern messagePattern =
        handshakePattern.getHandshakeMessagePatterns()[currentMessagePattern];

    for (final HandshakePattern.Token token : messagePattern.tokens()) {
      switch (token) {
        case E -> {
          if (remoteEphemeralPublicKey != null) {
            throw new IllegalStateException("Remote ephemeral key already set");
          }

          final byte[] ephemeralKeyBytes = new byte[keyAgreement.getPublicKeyLength()];
          System.arraycopy(message, offset, ephemeralKeyBytes, 0, ephemeralKeyBytes.length);

          remoteEphemeralPublicKey = keyAgreement.deserializePublicKey(ephemeralKeyBytes);

          mixHash(ephemeralKeyBytes);

          if (handshakePattern.isPreSharedKeyHandshake()) {
            mixKey(ephemeralKeyBytes);
          }

          offset += ephemeralKeyBytes.length;
        }

        case S -> {
          if (remoteStaticPublicKey != null) {
            throw new IllegalStateException("Remote static key already set");
          }

          final int staticKeyCiphertextLength = keyAgreement.getPublicKeyLength() + (cipherState.hasKey() ? 16 : 0);
          final byte[] staticKeyBytes = new byte[keyAgreement.getPublicKeyLength()];

          decryptAndHash(message, offset, staticKeyCiphertextLength, staticKeyBytes, 0);

          remoteStaticPublicKey = keyAgreement.deserializePublicKey(staticKeyBytes);

          offset += staticKeyCiphertextLength;
        }

        case EE, ES, SE, SS, PSK -> handleMixKeyToken(token);
      }
    }

    currentMessagePattern += 1;

    return decryptAndHash(message, offset, messageLength - offset, payload, payloadOffset);
  }

  private void handleMixKeyToken(final HandshakePattern.Token token) {
    try {
      switch (token) {
        case EE -> {
          if (localEphemeralKeyPair == null) {
            throw new IllegalStateException("No local ephemeral key available");
          }

          if (remoteEphemeralPublicKey == null) {
            throw new IllegalStateException("No remote ephemeral key available");
          }

          mixKey(keyAgreement.generateSecret(localEphemeralKeyPair.getPrivate(), remoteEphemeralPublicKey));
        }

        case ES -> {
          switch (role) {
            case INITIATOR -> {
              if (localEphemeralKeyPair == null) {
                throw new IllegalStateException("No local ephemeral key available");
              }

              if (remoteStaticPublicKey == null) {
                throw new IllegalStateException("No remote static key available");
              }

              mixKey(keyAgreement.generateSecret(localEphemeralKeyPair.getPrivate(), remoteStaticPublicKey));
            }
            case RESPONDER -> {
              if (localStaticKeyPair == null) {
                throw new IllegalStateException("No local static key available");
              }

              if (remoteEphemeralPublicKey == null) {
                throw new IllegalStateException("No remote ephemeral key available");
              }

              mixKey(keyAgreement.generateSecret(localStaticKeyPair.getPrivate(), remoteEphemeralPublicKey));
            }
          }
        }

        case SE -> {
          switch (role) {
            case INITIATOR -> {
              if (localStaticKeyPair == null) {
                throw new IllegalStateException("No local static key available");
              }

              if (remoteEphemeralPublicKey == null) {
                throw new IllegalStateException("No remote ephemeral key available");
              }

              mixKey(keyAgreement.generateSecret(localStaticKeyPair.getPrivate(), remoteEphemeralPublicKey));
            }
            case RESPONDER -> {
              if (localEphemeralKeyPair == null) {
                throw new IllegalStateException("No local ephemeral key available");
              }

              if (remoteStaticPublicKey == null) {
                throw new IllegalStateException("No remote static key available");
              }

              mixKey(keyAgreement.generateSecret(localEphemeralKeyPair.getPrivate(), remoteStaticPublicKey));
            }
          }
        }

        case SS -> {
          if (localStaticKeyPair == null) {
            throw new IllegalStateException("No local static key available");
          }

          if (remoteStaticPublicKey == null) {
            throw new IllegalStateException("No remote static key available");
          }

          mixKey(keyAgreement.generateSecret(localStaticKeyPair.getPrivate(), remoteStaticPublicKey));
        }

        case PSK -> {
          if (preSharedKeys == null || currentPreSharedKey >= preSharedKeys.size()) {
            throw new IllegalStateException("No pre-shared key available");
          }

          mixKeyAndHash(preSharedKeys.get(currentPreSharedKey++));
        }

        default -> throw new IllegalArgumentException("Unexpected key-mixing token: " + token.name());
      }
    } catch (final InvalidKeyException e) {
      // This should never happen. All keys have been parsed and validated either at construction time or upon arrival
      // from the other party.
      throw new AssertionError(e);
    }
  }

  /**
   * "Falls back" to the named handshake pattern, transferring any appropriate static/ephemeral keys and an empty
   * collection of pre-shared keys.
   *
   * @param handshakePatternName the name of the handshake pattern to which to fall back; must be a pattern with a
   *                             "fallback" modifier
   *
   * @return a new Noise handshake instance that implements the given fallback handshake pattern
   *
   * @throws NoSuchPatternException if the given fallback pattern name is not a recognized Noise handshake pattern name
   * or cannot be derived from a recognized Noise handshake pattern
   * @throws IllegalArgumentException if the given fallback pattern name is not a fallback pattern
   * @throws IllegalStateException if the given fallback pattern requires key material not available to the current
   * handshake
   *
   * @see <a href="https://noiseprotocol.org/noise.html#the-fallback-modifier">The Noise Protocol Framework - The fallback modifier</a>
   *
   * @see HandshakePattern#isFallbackPattern()
   */
  public NoiseHandshake fallbackTo(final String handshakePatternName) throws NoSuchPatternException {
    // TODO Self-destruct after falling back
    return fallbackTo(handshakePatternName, null);
  }

  /**
   * "Falls back" to the named handshake pattern, transferring any appropriate static/ephemeral keys and the given
   * collection of pre-shared keys.
   *
   * @param handshakePatternName the name of the handshake pattern to which to fall back; must be a pattern with a
   *                             "fallback" modifier
   * @param preSharedKeys the pre-shared keys to use in the fallback handshake; may be {@code null}
   *
   * @return a new Noise handshake instance that implements the given fallback handshake pattern
   *
   * @throws NoSuchPatternException if the given fallback pattern name is not a recognized Noise handshake pattern name
   * or cannot be derived from a recognized Noise handshake pattern
   * @throws IllegalArgumentException if the given fallback pattern name is not a fallback pattern
   * @throws IllegalStateException if the given fallback pattern requires key material not available to the current
   * handshake
   *
   * @see <a href="https://noiseprotocol.org/noise.html#the-fallback-modifier">The Noise Protocol Framework - The fallback modifier</a>
   *
   * @see HandshakePattern#isFallbackPattern()
   */
  public NoiseHandshake fallbackTo(final String handshakePatternName, @Nullable final List<byte[]> preSharedKeys) throws NoSuchPatternException {
    final HandshakePattern fallbackPattern = HandshakePattern.getInstance(handshakePatternName);

    if (!fallbackPattern.isFallbackPattern()) {
      throw new IllegalArgumentException(handshakePatternName + " is not a valid fallback pattern name");
    }

    @Nullable final KeyPair fallbackLocalStaticKeyPair;

    if (fallbackPattern.requiresLocalStaticKeyPair(role)) {
      if (localStaticKeyPair != null) {
        fallbackLocalStaticKeyPair = localStaticKeyPair;
      } else {
        throw new IllegalStateException("Fallback pattern requires a local static key pair, but none is available");
      }
    } else {
      fallbackLocalStaticKeyPair = null;
    }

    @Nullable final PublicKey fallbackRemoteStaticPublicKey;

    if (fallbackPattern.requiresRemoteStaticPublicKey(role)) {
      if (remoteStaticPublicKey != null) {
        fallbackRemoteStaticPublicKey = remoteStaticPublicKey;
      } else {
        throw new IllegalStateException("Fallback pattern requires a remote static public key, but none is available");
      }
    } else {
      fallbackRemoteStaticPublicKey = null;
    }

    @Nullable final PublicKey fallbackRemoteEphemeralPublicKey;

    if (fallbackPattern.requiresRemoteEphemeralPublicKey(role)) {
      if (remoteEphemeralPublicKey != null) {
        fallbackRemoteEphemeralPublicKey = remoteEphemeralPublicKey;
      } else {
        throw new IllegalStateException("Fallback pattern requires a remote ephemeral public key, but none is available");
      }
    } else {
      fallbackRemoteEphemeralPublicKey = null;
    }

    return new NoiseHandshake(role,
        fallbackPattern,
        keyAgreement,
        cipherState.getCipher(),
        noiseHash,
        prologue,
        fallbackLocalStaticKeyPair,
        localEphemeralKeyPair,
        fallbackRemoteStaticPublicKey,
        fallbackRemoteEphemeralPublicKey,
        preSharedKeys);
  }

  /**
   * Builds a bidirectional Noise transport object from this handshake. This method may be called exactly once, only if
   * this is a bidirectional (i.e. not one-way) handshake, and only when the handshake is done.
   *
   * @return a bidirectional Noise transport object derived from this completed handshake
   *
   * @throws IllegalStateException if this is a one-way handshake, the handshake has not finished, or this handshake has
   * previously been "split" into a Noise transport object
   *
   * @see #isDone()
   * @see #isOneWayHandshake()
   */
  public NoiseTransport toTransport() {
    if (handshakePattern.isOneWayPattern()) {
      throw new IllegalStateException("Cannot split a handshake for a one-way pattern into a bidirectional transport instance");
    }

    return split();
  }

  /**
   * Builds a read-only Noise transport object from this handshake. This method may be called exactly once, only if
   * this is a one-way handshake, only if this is the handshake for the responder, and only when the handshake is done.
   *
   * @return a read-only Noise transport object derived from this completed handshake
   *
   * @throws IllegalStateException if this is not a one-way handshake, if this method is called on the initiator side
   * of a one-way handshake, if the handshake has not finished, or this handshake has previously been "split" into a
   * Noise transport object
   *
   * @see #isDone()
   * @see #isOneWayHandshake()
   */
  public NoiseTransportReader toTransportReader() {
    if (!handshakePattern.isOneWayPattern()) {
      throw new IllegalStateException("Bidirectional handshakes may not be split into one-way transport objects");
    }

    if (role != Role.RESPONDER) {
      throw new IllegalStateException("Read-only transport objects may only be created for responders in one-way handshakes");
    }

    return split();
  }

  /**
   * Builds a write-only Noise transport object from this handshake. This method may be called exactly once, only if
   * this is a one-way handshake, only if this is the handshake for the initiator, and only when the handshake is done.
   *
   * @return a read-only Noise transport object derived from this completed handshake
   *
   * @throws IllegalStateException if this is not a one-way handshake, if this method is called on the responder side
   * of a one-way handshake, if the handshake has not finished, or this handshake has previously been "split" into a
   * Noise transport object
   *
   * @see #isDone()
   * @see #isOneWayHandshake()
   */
  public NoiseTransportWriter toTransportWriter() {
    if (!handshakePattern.isOneWayPattern()) {
      throw new IllegalStateException("Bidirectional handshakes may not be split into one-way transport objects");
    }

    if (role != Role.INITIATOR) {
      throw new IllegalStateException("Write-only transport objects may only be created for initiators in one-way handshakes");
    }

    return split();
  }

  private NoiseTransportImpl split() {
    if (!isDone()) {
      throw new IllegalStateException("Handshake is not finished and expects to exchange more messages");
    }

    if (hasSplit) {
      throw new IllegalStateException("Handshake has already been split into a Noise transport instance");
    }

    final byte[][] derivedKeys = noiseHash.deriveKeys(chainingKey, EMPTY_BYTE_ARRAY, 2);

    // We switch to "Bob-initiated" mode in fallback patterns
    final boolean isEffectiveInitiator =
        handshakePattern.isFallbackPattern() ? role == Role.RESPONDER : role == Role.INITIATOR;

    final CipherState readerCipherState = new CipherState(cipherState.getCipher());
    readerCipherState.setKey(derivedKeys[isEffectiveInitiator ? 1 : 0]);

    final CipherState writerCipherState = new CipherState(cipherState.getCipher());
    writerCipherState.setKey(derivedKeys[isEffectiveInitiator ? 0 : 1]);

    hasSplit = true;

    return new NoiseTransportImpl(readerCipherState, writerCipherState);
  }
}
