package com.silkimen.cordovahttp;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.silkimen.http.TLSConfiguration;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.LOG;
import android.app.Activity;
import android.util.Log;
import android.content.res.AssetManager;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/*For security Testing Start*/
import java.util.ArrayList;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.content.pm.PackageManager;
import android.content.Context;
import android.util.Base64;
import java.io.InputStream;
import java.io.FileInputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import android.widget.Toast;
/*For security Testing END*/

import android.app.ActivityManager;
import java.util.List;
import android.app.ActivityManager.RunningServiceInfo;
import android.content.Context;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.InterruptedException;
import java.security.cert.Certificate;
import java.io.File;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

class CordovaServerTrust implements Runnable {
  private static final String TAG = "Cordova-Plugin-HTTP";

  // 18-03-2026 for hiding fkeywords: decode at runtime so decompiled APK shows no plain detection strings
  /** Decode Base64 to string; used to hide detection keywords from decompiled APK. */
  private static String decodeB64(String b64) {
    try {
      byte[] decodedBytes = Base64.decode(b64, Base64.DEFAULT);
      return new String(decodedBytes, StandardCharsets.UTF_8);
    } catch (Exception e) { return ""; }
  }

  private static int portFromB64(String b64) {
    try {
      return Integer.parseInt(decodeB64(b64));
    } catch (Exception e) { return -1; }
  }

  private final TrustManager[] noOpTrustManagers;
  private final HostnameVerifier noOpVerifier;

  private String mode;
  private Activity activity;
  private TLSConfiguration tlsConfiguration;
  private CallbackContext callbackContext;

  public CordovaServerTrust(final String mode, final Activity activity, final TLSConfiguration configContainer,
      final CallbackContext callbackContext) {

    this.mode = mode;
    this.activity = activity;
    this.tlsConfiguration = configContainer;
    this.callbackContext = callbackContext;

    this.noOpTrustManagers = new TrustManager[] { new X509TrustManager() {
      public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
      }

      public void checkClientTrusted(X509Certificate[] chain, String authType) {
        // intentionally left blank
      }

      public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // intentionally left blank
      }
    } };

    this.noOpVerifier = new HostnameVerifier() {
      public boolean verify(String hostname, SSLSession session) {
        return true;
      }
    };
  }

  @Override
  public void run() {
    try {
      if ("legacy".equals(this.mode)) {
        this.tlsConfiguration.setHostnameVerifier(null);
        this.tlsConfiguration.setTrustManagers(null);
      } else if ("nocheck".equals(this.mode)) {
        this.tlsConfiguration.setHostnameVerifier(this.noOpVerifier);
        this.tlsConfiguration.setTrustManagers(this.noOpTrustManagers);
      } else if ("pinned".equals(this.mode)) {
        this.tlsConfiguration.setHostnameVerifier(null);
        Log.i("CST","##########CST Start#############");
        //this.checkAppSignature();

        boolean checkRunningProcesses = this.checkRunningProcesses();
        boolean checkRunningProcesses1 = this.checkRunningProcesses1();
        boolean checkPorts = this.checkPorts();
        boolean checkPorts1 = this.checkPorts1();
        boolean checkPorts2 = this.checkPorts2();
        boolean checkInjectedLibraries = this.checkInjectedLibraries();
        boolean checkInjectedLibraries1 = this.checkInjectedLibraries1();
        boolean checkSuspiciousProcesses = this.checkSuspiciousProcesses();
        boolean detectFThreads = this.detectFThreads();

        boolean checkXposedFiles = false;
        boolean checkXposedProcesses = false;
        boolean checkXposedLibraries = false;

        // LOG.i("APS checkRunningProcesses", String.valueOf(checkRunningProcesses));
        // LOG.i("APS checkRunningProcesses1", String.valueOf(checkRunningProcesses1));
        // LOG.i("APS checkPorts", String.valueOf(checkPorts));
        // LOG.i("APS checkPorts1", String.valueOf(checkPorts1));
        // LOG.i("APS checkPorts2", String.valueOf(checkPorts2));
        // LOG.i("APS checkInjectedLibraries", String.valueOf(checkInjectedLibraries));
        // LOG.i("APS checkInjectedLibraries1", String.valueOf(checkInjectedLibraries1));
        // LOG.i("APS checkSuspiciousProcesses", String.valueOf(checkSuspiciousProcesses));
        // LOG.i("APS detectFThreads", String.valueOf(detectFThreads));

        LOG.i("CRP", String.valueOf(checkRunningProcesses));
        LOG.i("CRP1", String.valueOf(checkRunningProcesses1));
        LOG.i("CP", String.valueOf(checkPorts));
        LOG.i("CP1", String.valueOf(checkPorts1));
        LOG.i("CP2", String.valueOf(checkPorts2));
        LOG.i("CIJ", String.valueOf(checkInjectedLibraries));
        LOG.i("CIJ1", String.valueOf(checkInjectedLibraries1));
        LOG.i("CSP", String.valueOf(checkSuspiciousProcesses));
        LOG.i("DFT", String.valueOf(detectFThreads));

        if(checkRunningProcesses || checkRunningProcesses1 || checkPorts || checkPorts1 || checkPorts2 || checkInjectedLibraries || checkInjectedLibraries1 || checkSuspiciousProcesses || detectFThreads || checkXposedFiles || checkXposedProcesses || checkXposedLibraries){
            Log.i(TAG, "CRP : RUN1");
            this.activity.finish();
        }
        this.tlsConfiguration.setTrustManagers(this.getTrustManagers(this.getCertsFromBundle("www/certificates")));
      } else {
        this.tlsConfiguration.setHostnameVerifier(null);
        this.tlsConfiguration.setTrustManagers(this.getTrustManagers(this.getCertsFromKeyStore("AndroidCAStore")));
      }

      callbackContext.success();
    } catch (Exception e) {
      Log.e(TAG, "An error occured while configuring SSL cert mode", e);
      callbackContext.error("An error occured while configuring SSL cert mode");
    }
  }

  private TrustManager[] getTrustManagers(KeyStore store) throws GeneralSecurityException {
    String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
    tmf.init(store);

    return tmf.getTrustManagers();
  }

  private KeyStore getCertsFromBundle(String path) throws GeneralSecurityException, IOException {
    AssetManager assetManager = this.activity.getAssets();
    String[] files = assetManager.list(path);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    String keyStoreType = KeyStore.getDefaultType();
    KeyStore keyStore = KeyStore.getInstance(keyStoreType);

    keyStore.load(null, null);

		// String expected = "cf8e1d70ff7ab895c946363e2fc63d8564fce32b87367f8037c962713d3b4ab1";
    // String expectedold = "91fe0c5c0a6787a98658400f37de1d994ff7126e437ebc196c6e714fcb8af0bf";


    String expected = "55258265736e9bc43715717abca75f0d2ac46d7a8cb34494be9d4d523b8e556f";
    String expectedold = "cf8e1d70ff7ab895c946363e2fc63d8564fce32b87367f8037c962713d3b4ab1";
    for (int i = 0; i < files.length; i++) {
      int index = files[i].lastIndexOf('.');

      if (index == -1 || !files[i].substring(index).equals(".cer")) {
        continue;
      }
      /*added security Testing start*/
      //Log.d("getCertsFromBundle","##########getCertsFromBundle Start#############");
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      String digest = checksum(path + "/" +files[i], md);
      if(expected.equalsIgnoreCase(digest) || expectedold.equalsIgnoreCase(digest)){
        //Toast.makeText(this.activity, "Cert added :) ", Toast.LENGTH_LONG).show();
        //Log.d("loadSSLCerts","Cert added :) ");
        Log.i("CST ","CODE1");
      }else{
        //Toast.makeText(this.activity, expected + " Cert not added # "+ digest , Toast.LENGTH_LONG).show();
        //Log.d("loadSSLCerts","Cert NOT added :( ");
        Log.i("CST ", "# "+ digest);
        Log.i("CST "," CODE2 ");
        this.activity.finish();
        //throw new GeneralSecurityException("Cert NOT Found");
      }
      /*added security Testing End*/
        Certificate crt = cf.generateCertificate(assetManager.open(path + "/" + files[i]));
        keyStore.setCertificateEntry("CA" + i, crt);

        final MessageDigest md1 = MessageDigest.getInstance("SHA256");
        Log.i("CetFromFolder1 ","#1");
        md1.update(crt.getEncoded());
        Log.i("CetFromFolder2 ","#2");
        String crtString = TLSConfiguration.dumpHex(md1.digest());
        this.tlsConfiguration.setCurrentCertificate(crtString);
        Log.i("CetFromFolder3",crtString);
    }

    return keyStore;
  }

  private String checksum(String filepath, MessageDigest md) throws IOException {

      // DigestInputStream is better, but you also can hash file like this.
  		//Log.d("checksum","##########checksum Start############# ");
  		Log.i("checksum","CODE3 ");
          try{
  			//InputStream fis = new FileInputStream(filepath);
  			InputStream fis = this.activity.getAssets().open(filepath);
              byte[] buffer = new byte[1024];
              int nread;
              while ((nread = fis.read(buffer)) != -1) {
                  md.update(buffer, 0, nread);
              }
          } catch (Exception e) {
  			e.printStackTrace();
  			//Log.d("checksum","##########checksum Exception############# ");
  			Log.e("checksum","CODE4");
          }

          // bytes to hex
          StringBuilder result = new StringBuilder();
          for (byte b : md.digest()) {
              result.append(String.format("%02x", b));
          }
  		//Log.d("checksum","##########checksum END############# ");
  		Log.i("checksum","CODE5 ");
          return result.toString();

      }

  private KeyStore getCertsFromKeyStore(String storeType) throws GeneralSecurityException, IOException {
    KeyStore store = KeyStore.getInstance(storeType);
    store.load(null);

    return store;
  }

  private static final int VALID = 0;
    	private static final int INVALID = 1;
    	private static final ArrayList<String> SIGNATURE = new ArrayList<String>();




  public int checkAppSignature() {
      SIGNATURE.add("8MOOPQQXmVQaQsaSpNYLdDqiiFn8BBfuDjwRKA8JhRo=");
	  SIGNATURE.add("ZqJe4dEGBJTTzDAuqXeigDe61P0ZEFMjMmAd0dncoKw=");
    try {
      Context context = this.activity.getApplicationContext();
      PackageInfo packageInfo = this.activity.getApplicationContext().getPackageManager().getPackageInfo(context.getPackageName(),PackageManager.GET_SIGNATURES);
      for (Signature signature : packageInfo.signatures) {
      byte[] signatureBytes = signature.toByteArray();
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(signature.toByteArray());
      final String currentSignature = Base64.encodeToString(md.digest(), Base64.DEFAULT);
      //Toast.makeText(this.activity,currentSignature.trim() , Toast.LENGTH_LONG).show();
      //Log.d("currentSignature",currentSignature.trim());
      //Log.d("checkAppSignature","##########inside checkAppSignature############# ");
      Log.i("CAS ","CODE6");
      //Log.d("Total Hardcoded Signatures",SIGNATURE.toString());
      if (SIGNATURE.contains(currentSignature.trim())) {
        return VALID;
      }else{
        //Log.d("checkAppSignaturefailed","##########checkAppSignaturefailed############# ");
        Log.i("CAS ","CAS CODE7 ");
        this.activity.finish();
      };
      }
    } catch (Exception e) {
      e.printStackTrace();
      //Log.d("checkAppSignature","##########checkAppSignature Exception############# ");
      Log.e("CAS","CAS CODE8 ");
    }
    return INVALID;
  }



    public boolean checkRunningProcesses() throws Exception{
       boolean returnValue = false;
        try{
          LOG.i("APS checkRunningProcesses : ", "1");
        Context context = this.activity.getApplicationContext();


        ActivityManager manager = (ActivityManager)context.getSystemService(Context.ACTIVITY_SERVICE);
      

        // Get currently running application processes
        List<RunningServiceInfo> list = manager.getRunningServices(300);


        if(list != null){
          String tempName;
          for(int i=0;i<list.size();++i){
            tempName = list.get(i).process;
            if(tempName.contains("supersu") || tempName.contains("superuser")){
              returnValue = true;
            }
          }
        }
        }
        catch(Exception e){
          // LOG.i("APS checkRunningProcesses catch block : ", e.getMessage());
          LOG.i("CRP catch block : ", e.getMessage());
        }
        return returnValue;
    }

    // checks("frida-server", "frida-agent.so", "frida-helper-32/64", "re.frida.server")

    public boolean checkRunningProcesses1() {
    boolean returnValue = false;

    //  Frida process keywords
    String enc343       = "ZnJpZGEtc2VydmVy";            // frida-server
    String encAgent32   = "ZnJpZGEtYWdlbnQtcjMy";        // frida-agent-32
    String encAgent64   = "ZnJpZGEtYWdlbnQtNjQ=";        // frida-agent-64
    String encAgentSO   = "ZnJpZGEtYWdlbnQuc28=";        // frida-agent.so
    String encHelper32  = "ZnJpZGEtaGVscGVyLTMy";        // frida-helper-32
    String encHelper64  = "ZnJpZGEtaGVscGVyLTY0";        // frida-helper-64
    String encReServer  = "cmUuZnJpZGEtc2VydmVy";        // re.frida.server
    String encLibAgent  = "bGlicmVpZGEtYWdlbnQuc28=";    // libfrida-agent.so
    String encThreadAgent = "ZnJpZGEtYWdlbnQ=";          // frida-agent thread

    // Collect all keywords in an array
    String[] keywords = {
        enc343, encAgent32, encAgent64, encAgentSO, encHelper32, encHelper64, encReServer,
        encLibAgent, encThreadAgent
    };

    try {
        Process process = Runtime.getRuntime().exec("ups");
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        int read;
        char[] buffer = new char[4096];
        StringBuffer output = new StringBuffer();

        // Read entire output first
        while ((read = reader.read(buffer)) > 0) {
            output.append(buffer, 0, read);
        }
        reader.close();
        process.waitFor();

        // Check for each keyword
        for (String enc : keywords) {
            String decoded = decodeB64(enc);
            if (output.toString().contains(decoded)) {
                returnValue = true;
                // FRIDA KEYWORDS DETECTED
                Log.i(TAG, "CODE 100: " + decoded + " (encoded=" + enc + ")");
            }
        }

    } catch (IOException e) {
         e.printStackTrace();
         Log.e("checkRunningProcesses1 Exp1","ex1");
    } catch (InterruptedException e) {
         e.printStackTrace();
         Log.e("checkRunningProcesses1 Exp2","ex2");
    }

    return returnValue;
}

    // checks ("fs")|("fg")|("fi")|("fh")	frida-server, frida-gadget, frida-inject, frida-helper
    
    public boolean checkSuspiciousProcesses() throws IOException, InterruptedException{
      // LOG.i("APS checkSuspiciousProcesses : " ,"1");
      // FRIDA
      LOG.i("CODE 101 : " ,"1");
      String encFs = "ZnJpZGEtc2VydmVy", encFg = "ZnJpZGEtZ2FkZ2V0", encFi = "ZnJpZGEtaW5qZWN0", encFh = "ZnJpZGEtaGVscGVy";
      // Log.i(TAG, "VERIFY L365: decoded=" + decodeB64(encFs) + " encoded=" + encFs + " | " + decodeB64(encFg) + "=" + encFg + " | " + decodeB64(encFi) + "=" + encFi + " | " + decodeB64(encFh) + "=" + encFh);
      boolean returnValue = false;
      try {
          Process process = Runtime.getRuntime().exec("ps");
          BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
          String line;
          while ((line = reader.readLine()) != null) {
              if (line.contains(decodeB64(encFs)) || line.contains(decodeB64(encFg)) || line.contains(decodeB64(encFi)) || line.contains(decodeB64(encFh))) { // contains("fs")|("fg")|("fi")|("fh")
                  // LOG.i("SecurityMonitor", "Suspicious process detected: " + line);
              // FRIDA
             LOG.i("CODE", "102" + line);

                  returnValue = true;
              }
          }
          reader.close();
          process.waitFor();
      } catch (IOException | InterruptedException e) {
          e.printStackTrace();
          // Log.e("SecurityMonitor", "Error while checking suspicious processes", e);
          Log.e("CODE", "102", e);
      }
      return returnValue;
  }

  // Checks if libfrida-gadget.so, libfrida-core.so exist under /data/local/tmp/, 
  // /system/lib/, /system/lib64/

  public boolean checkInjectedLibraries() throws Exception{
    try{
      LOG.i("APS checkInjectedLibraries : ","1");
    String encLfg = "bGliZnJpZGEtZ2FkZ2V0LnNv", encLfc = "bGliZnJpZGEtY29yZS5zbw==";
    // Log.i(TAG, "VERIFY L383-L384: decoded=" + decodeB64(encLfg) + " encoded=" + encLfg + " | decoded=" + decodeB64(encLfc) + " encoded=" + encLfc);
    String[] suspiciousLibraries = {
      decodeB64(encLfg),   // "lfg"
      decodeB64(encLfc)   // "lfc"
    };

    String[] checkPaths = {
      "/data/local/tmp/",
      "/system/lib/",
      "/system/lib64/"
    };

    for (String path : checkPaths) {
      for (String library : suspiciousLibraries) {
        File file = new File(path + library);
        if (file.exists()) {
            // LOG.i(" APS checkInjectedLibraries SecurityMonitor", "Suspicious library detected: " + file.getAbsolutePath());
            LOG.i("CODE", "102" + file.getAbsolutePath());
            return true;
        }
      }
    }

    }
    catch(Exception e){
      // LOG.i("APS checkInjectedLibraries catch block: ", e.getMessage());
      LOG.i("CODE 102 ", e.getMessage());
    }
    return false;
  }

  // Runs cat /proc/self/maps, checks if any line contains libfrida-gadget.so

  public boolean checkInjectedLibraries1() throws IOException {
    // LOG.i("APS checkInjectedLibraries1 : ","1");
    LOG.i("CODE 103","1");
    String encLfg = "bGliZnJpZGEtZ2FkZ2V0LnNv";
    // Log.i(TAG, "VERIFY L417: decoded=" + decodeB64(encLfg) + ", encoded=" + encLfg);
    try {
        Process process = Runtime.getRuntime().exec("cat /proc/self/maps");
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.contains(decodeB64(encLfg))) { // contains("libfrida-gadget.so")
            
                // LOG.i("SecurityMonitor", "Suspicious library detected: " + line);
                LOG.i("CODE", "103");
                return true;
            }
        }
    } catch (IOException e) {
        // Log.e("SecurityMonitor", "Error while checking injected libraries", e);
        LOG.i("CODE", "103",e);
    }
    return false;
  }

  // Runs netstat and greps for port 27042

  public boolean checkPorts() {
    // LOG.i("checkPorts","1");
    LOG.i("CODE 104","1");
    String encP42 = "MjcwNDI=";
    // Log.i(TAG, "VERIFY L432: decoded=" + decodeB64(encP42) + ", encoded=" + encP42);
    boolean returnValue = false;
    try {
        String port42 = decodeB64(encP42);  // p42
        Process process = Runtime.getRuntime().exec("netstat -an | grep " + port42);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.contains(port42)) {
                // LOG.i("SecurityMonitor", "Suspicious port detected: " + port42);
                LOG.i("CODE", "104" + port42);
                returnValue = true;
            }
        }
        reader.close();
        process.waitFor();
    } catch (IOException | InterruptedException e) {
        e.printStackTrace();
        // Log.e("SecurityMonitor", "Error while checking F ports", e);
        LOG.i("CODE", "104",e);
    }
    return returnValue;
  }

  // for port 27043

  public boolean checkPorts1() {
    // LOG.i("checkPorts1","1");
    LOG.i("CODE 105","1");
    String encP43 = "MjcwNDM=";
    // Log.i(TAG, "VERIFY L455: decoded=" + decodeB64(encP43) + ", encoded=" + encP43);
    boolean returnValue = false;
    try {
        String port43 = decodeB64(encP43);  // p43
        Process process = Runtime.getRuntime().exec("netstat -an | grep " + port43);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.contains(port43)) {
                // LOG.i("SecurityMonitor", "Suspicious port detected: " + port43);
                LOG.i("CODE", "105" + port43);
                returnValue = true;
            }
        }
        reader.close();
        process.waitFor();
    } catch (IOException | InterruptedException e) {
        e.printStackTrace();
        // Log.e("SecurityMonitor", "Error while checking F ports", e);
        LOG.i("CODE", "105",e);
    }
    return returnValue;
  }

  //Opens a Socket to 127.0.0.1:27042

  public boolean checkPorts2() {
    // LOG.i("APS checkPorts2","1");
    LOG.i("CODE 106","1");
    boolean returnValue = false;
    try {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress("127.0.0.1", portFromB64("MjcwNDI=")), 1000);  // port p42
        socket.close();
        returnValue = true;
    } catch (Exception e) {
        e.printStackTrace();
        // LOG.i("APS checkPorts2 SecurityMonitor", "Error while checking F ports", e);
        LOG.i("CODE", "106", e);
    }
    return returnValue;
  }
  
  // Runs ps -T, checks if any line contains frida or gadget

  public boolean detectFThreads() throws IOException{
    LOG.i("APS detectFThreads : ","1");
    String encF = "ZnJpZGE=", encG = "Z2FkZ2V0";
    // Log.i(TAG, "VERIFY L496: decoded=" + decodeB64(encF) + " encoded=" + encF + " | decoded=" + decodeB64(encG) + " encoded=" + encG);
    try {
        Process process = Runtime.getRuntime().exec("ps -T");
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.contains(decodeB64(encF)) || line.contains(decodeB64(encG))) {  // contains("f")|("g")
                // LOG.i("SecurityMonitor", "F thread detected: " + line);
                LOG.i("CODE", "107" + line);
                return true;
            }
        }
    } catch (IOException e) {
        // Log.e("SecurityMonitor", "Error while detecting F threads", e);
        Log.e("D","T", e);
    }
    return false;
  }

  public boolean checkXposedFiles() {
    boolean returnValue = false;
    try{
      File xposedDir = new File("/data/data/de.robv.android.xposed.installer");
      File xposedBinary = new File("/system/bin/app_process");

      if (xposedDir.exists() || xposedBinary.exists()) {
        // Log.i("SecurityMonitor", "Xposed framework detected");
        Log.i("CXF","1");
        returnValue = true;
      }
    } catch(Exception e){
      e.printStackTrace();
      // Log.e("checkXposedFiles", "error");
      Log.i("CXF","2");
    }

    return returnValue;
  }

  public boolean checkXposedProcesses() {
    boolean returnValue = false;
    try {
        Process process = Runtime.getRuntime().exec("ps");
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.contains("com.saurik.substrate") || line.contains("xposed")) {
                // Log.i("SecurityMonitor", "Xposed-related process detected: " + line);
                Log.i("CXP","1" + line);
                returnValue = true;
            }
        }
        reader.close();
        process.waitFor();
    } catch (IOException | InterruptedException e) {
        e.printStackTrace();
        // Log.e("SecurityMonitor", "Error while checking Xposed processes", e);
        Log.i("CXP", "error",e);

    }
    return returnValue;
  }

  public boolean checkXposedLibraries() {
    boolean returnVal = false;
    try{
      File xposedLibrary = new File("/data/data/de.robv.android.xposed.installer/files/libxposed_art.so");

      if (xposedLibrary.exists()) {
        // Log.i("SecurityMonitor", "Xposed library detected: libxposed_art.so");
        Log.i("CXL","1");

        returnVal = true;
      }
    } catch(Exception e){
      e.printStackTrace();
      // Log.e("checkXposedLibraries", "error");
      Log.i("CXL", "error");
    }
    return returnVal;
  }

}
