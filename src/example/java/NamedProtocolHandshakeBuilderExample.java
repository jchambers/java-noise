import com.eatthepath.noise.NamedProtocolHandshakeBuilder;
import com.eatthepath.noise.NoSuchPatternException;
import com.eatthepath.noise.NoiseHandshake;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

@SuppressWarnings("NewClassNamingConvention")
public class NamedProtocolHandshakeBuilderExample {

  @SuppressWarnings("unused")
  @Test
  void buildNNHandshake() throws NoSuchAlgorithmException, NoSuchPatternException {
    final String nnProtocolName = "Noise_NN_25519_ChaChaPoly_SHA256";

    // @start region="nn-handshake"
    final NoiseHandshake nnInitiatorHandshake =
        new NamedProtocolHandshakeBuilder(nnProtocolName, NoiseHandshake.Role.INITIATOR).build();

    final NoiseHandshake nnResponderHandshake =
        new NamedProtocolHandshakeBuilder(nnProtocolName, NoiseHandshake.Role.RESPONDER).build();
    // @end
  }

  @SuppressWarnings("unused")
  @Test
  void buildIKHandshake() throws NoSuchAlgorithmException, NoSuchPatternException {
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("X25519");
    final KeyPair initiatorLocalStaticKeyPair = keyPairGenerator.generateKeyPair();
    final KeyPair responderLocalStaticKeyPair = keyPairGenerator.generateKeyPair();
    final PublicKey initiatorRemoteStaticPublicKey = responderLocalStaticKeyPair.getPublic();

    final String ikProtocolName = "Noise_IK_25519_ChaChaPoly_SHA256";

    // @start region="ik-handshake"
    final NoiseHandshake ikInitiatorHandshake =
        new NamedProtocolHandshakeBuilder(ikProtocolName, NoiseHandshake.Role.INITIATOR)
            .setLocalStaticKeyPair(initiatorLocalStaticKeyPair)
            .setRemoteStaticPublicKey(initiatorRemoteStaticPublicKey)
            .build();

    final NoiseHandshake ikResponderHandshake =
        new NamedProtocolHandshakeBuilder(ikProtocolName, NoiseHandshake.Role.RESPONDER)
            .setLocalStaticKeyPair(responderLocalStaticKeyPair)
            .build();
    // @end
  }
}
