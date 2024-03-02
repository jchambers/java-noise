import com.eatthepath.noise.HandshakePattern;
import com.eatthepath.noise.NoSuchPatternException;
import org.junit.jupiter.api.Test;

@SuppressWarnings("NewClassNamingConvention")
public class HandshakePatternExample {

  @Test
  void getInstance() throws NoSuchPatternException {
    // @start region="get-instance"
    final HandshakePattern xxHandshakePattern = HandshakePattern.getInstance("XX");

    final HandshakePattern xxFallbackWithPskHandshakePattern =
        HandshakePattern.getInstance("XXfallback+psk0");
    // @end
  }
}
