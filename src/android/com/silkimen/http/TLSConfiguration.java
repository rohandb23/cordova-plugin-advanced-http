package com.silkimen.http;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.security.cert.Certificate;

import com.silkimen.http.TLSSocketFactory;

public class TLSConfiguration {
  private TrustManager[] trustManagers = null;
  private KeyManager[] keyManagers = null;
  private HostnameVerifier hostnameVerifier = null;
  private String[] blacklistedProtocols = {};
	private String currentCertificate;

  private SSLSocketFactory socketFactory;

    public String getCurrentCertificate() {
        return this.currentCertificate;
    }
    public void setCurrentCertificate(String crt) {
        this.currentCertificate = crt;
    }
  public void setHostnameVerifier(HostnameVerifier hostnameVerifier) {
    this.hostnameVerifier = hostnameVerifier;
  }

  public void setKeyManagers(KeyManager[] keyManagers) {
    this.keyManagers = keyManagers;
    this.socketFactory = null;
  }

  public void setTrustManagers(TrustManager[] trustManagers) {
    this.trustManagers = trustManagers;
    this.socketFactory = null;
  }

  public void setBlacklistedProtocols(String[] protocols) {
    this.blacklistedProtocols = protocols;
    this.socketFactory = null;
  }

  public HostnameVerifier getHostnameVerifier() {
    return this.hostnameVerifier;
  }

  public SSLSocketFactory getTLSSocketFactory() throws IOException {
    if (this.socketFactory != null) {
      return this.socketFactory;
    }

    try {
      SSLContext context = SSLContext.getInstance("TLS");

      context.init(this.keyManagers, this.trustManagers, new SecureRandom());
      this.socketFactory = new TLSSocketFactory(context, this.blacklistedProtocols);

      return this.socketFactory;
    } catch (GeneralSecurityException e) {
      IOException ioException = new IOException("Security exception occured while configuring TLS context");
      ioException.initCause(e);
      throw ioException;
    }
  }

  private static char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

   public static String dumpHex(byte[] data) {
      final int n = data.length;
      final StringBuilder sb = new StringBuilder(n * 3 - 1);
      for (int i = 0; i < n; i++) {
        if (i > 0) {
          sb.append(' ');
        }
        sb.append(HEX_CHARS[(data[i] >> 4) & 0x0F]);
        sb.append(HEX_CHARS[data[i] & 0x0F]);
      }
      return sb.toString();
    }
}
