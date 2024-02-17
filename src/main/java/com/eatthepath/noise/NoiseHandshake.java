package com.eatthepath.noise;

import javax.annotation.Nullable;
import javax.crypto.AEADBadTagException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class NoiseHandshake {

  private final String noiseProtocolName;
  private final HandshakePattern handshakePattern;
  private final Role role;

  private int currentMessagePattern = 0;

  private final CipherState cipherState;
  private final MessageDigest messageDigest;
  private final Mac mac;
  private final NoiseKeyAgreement keyAgreement;

  private final byte[] chainingKey;
  private final byte[] hash;

  @Nullable
  private KeyPair localEphemeralKeyPair;

  @Nullable
  private PublicKey remoteEphemeralPublicKey;

  @Nullable
  private KeyPair localStaticKeyPair;

  @Nullable
  private PublicKey remoteStaticPublicKey;

  public enum Role {
    INITIATOR,
    RESPONDER
  }

  public NoiseHandshake(final String noiseProtocolName,
                        final HandshakePattern handshakePattern,
                        final Role role,
                        final CipherState cipherState,
                        final MessageDigest messageDigest,
                        final Mac mac,
                        final NoiseKeyAgreement keyAgreement,
                        @Nullable final byte[] prologue,
                        @Nullable final KeyPair localStaticKeyPair,
                        @Nullable final KeyPair localEphemeralKeyPair,
                        @Nullable final PublicKey remoteStaticPublicKey,
                        @Nullable final PublicKey remoteEphemeralPublicKey) {

    this.noiseProtocolName = noiseProtocolName;
    this.handshakePattern = handshakePattern;
    this.role = role;

    this.cipherState = cipherState;
    this.messageDigest = messageDigest;
    this.mac = mac;
    this.keyAgreement = keyAgreement;

    hash = new byte[messageDigest.getDigestLength()];

    final byte[] protocolNameBytes = noiseProtocolName.getBytes(StandardCharsets.UTF_8);

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
  }

  private byte[][] hkdf(final byte[] inputKeyMaterial, final int outputKeys) {
    if (outputKeys < 2 || outputKeys > 3) {
      throw new IllegalArgumentException("Illegal output key count");
    }

    final byte[][] derivedKeys = new byte[messageDigest.getDigestLength()][outputKeys];

    try {
      mac.init(new SecretKeySpec(chainingKey, "RAW"));
      final Key tempKey = new SecretKeySpec(mac.doFinal(inputKeyMaterial), "RAW");

      for (byte k = 0; k < outputKeys; k++) {
        mac.init(tempKey);

        if (k > 0) {
          mac.update(derivedKeys[k - 1]);
        }

        mac.update((byte) (k + 1));
        derivedKeys[k] = mac.doFinal();
      }

      return derivedKeys;
    } catch (final InvalidKeyException e) {
      // This should never happen for keys we derive/control
      throw new AssertionError(e);
    }
  }

  private void mixKey(final byte[] inputKeyMaterial) {
    final byte[][] derivedKeys = hkdf(inputKeyMaterial, 2);

    System.arraycopy(derivedKeys[0], 0, chainingKey, 0, derivedKeys[0].length);

    // TODO Truncate to 32 bytes
    cipherState.setKey(new SecretKeySpec(derivedKeys[1], "RAW"));
  }

  private void mixHash(final byte[] bytes) {
    try {
      messageDigest.reset();
      messageDigest.update(hash);
      messageDigest.digest(hash, 0, hash.length);
    } catch (final DigestException e) {
      // This should never happen
      throw new AssertionError(e);
    }
  }

  private byte[] encryptAndHash(final byte[] plaintext) {
    final byte[] ciphertext = cipherState.encrypt(hash, plaintext);
    mixHash(ciphertext);

    return ciphertext;
  }

  private byte[] decryptAndHash(final byte[] ciphertext) throws AEADBadTagException {
    final byte[] plaintext = cipherState.decrypt(hash, ciphertext);
    mixHash(ciphertext);

    return plaintext;
  }

  private boolean expectingRead() {
    if (currentMessagePattern < handshakePattern.handshakeMessagePatterns().length) {
      return handshakePattern.handshakeMessagePatterns()[currentMessagePattern].sender() != role;
    }

    // We've completed the whole handshake, so we're not expecting any more messages
    return false;
  }

  public int getOutboundMessageLength(final int payloadLength) {
    if (handshakePattern.handshakeMessagePatterns()[currentMessagePattern].sender() != role) {
      throw new IllegalArgumentException("Handshake is not currently expecting to send a message");
    }

    return getOutboundMessageLength(handshakePattern, currentMessagePattern, keyAgreement.getPublicKeyLength(), payloadLength);
  }

  // Visible for testing
  static int getOutboundMessageLength(final HandshakePattern handshakePattern,
                                      final int message,
                                      final int publicKeyLength,
                                      final int payloadLength) {

    if (message < 0 || message >= handshakePattern.handshakeMessagePatterns().length) {
      throw new IndexOutOfBoundsException(
          String.format("Message index must be between 0 and %d for this handshake pattern, but was %d",
              handshakePattern.handshakeMessagePatterns().length, message));
    }

    boolean hasKey = false;

    // Run through all of this handshake's message patterns to see if we have a key prior to reaching the message of
    // interest
    for (int i = 0; i < message; i++) {
      for (final HandshakePattern.Token token : handshakePattern.handshakeMessagePatterns()[i].tokens()) {
        switch (token) {
          case EE, ES, SE, SS -> hasKey = true;
          default -> {}
        }
      }

      // No need to analyze additional message patterns if we already know we have a key
      if (hasKey) {
        break;
      }
    }

    int messageLength = 0;

    for (final HandshakePattern.Token token : handshakePattern.handshakeMessagePatterns()[message].tokens()) {
      switch (token) {
        case E -> messageLength += publicKeyLength;
        case S -> {
          messageLength += publicKeyLength;

          if (hasKey) {
            // If we have a key, then the static key is encrypted and has a 16-byte AEAD tag
            messageLength += 16;
          }
        }
        case EE, ES, SE, SS -> hasKey = true;
      }
    }

    messageLength += payloadLength;

    if (hasKey) {
      // If we have a key, then the payload is encrypted and has a 16-byte AEAD tag
      messageLength += 16;
    }

    return messageLength;
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
}
