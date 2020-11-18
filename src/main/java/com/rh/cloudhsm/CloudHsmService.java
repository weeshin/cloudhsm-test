package com.rh.cloudhsm;

import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.ImportKey;
import com.cavium.cfm2.LoginManager;
import com.cavium.cfm2.Util;
import com.cavium.key.CaviumDES3Key;
import com.cavium.key.CaviumKey;
import com.cavium.key.parameter.CaviumKeyGenAlgorithmParameterSpec;
import org.jpos.iso.ISOUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PreDestroy;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

/**
 * @author nicklim
 */
public class CloudHsmService {
    private final static Logger log = LoggerFactory.getLogger(CloudHsmService.class);
    private KeyStore keyStore;

    private String provider = "Cavium";


    public CloudHsmService(KeyStore keyStore) {
        this.keyStore = keyStore;
        log.info("CloudHsmServiceInit provider {}", provider);
    }

    @PreDestroy
    public void logout() throws Exception {
        log.info("Spring Container is destroyed! Logout HSM");
        try {
            LoginManager.getInstance().logout();
        } catch (CFM2Exception e) {
            e.printStackTrace();
        }
    }
    public void loginWithExplicitCredentials(String user, String pass, String partition) {
        LoginManager lm = LoginManager.getInstance();
        try {
            lm.login(partition, user, pass);
            log.info("Login successful!");
        } catch (CFM2Exception e) {
            if (CFM2Exception.isAuthenticationFailure(e)) {
                log.info("Detected invalid credentials");
            }

            log.error("Login Fail", e);
        }
    }
//    public Key getZak() {
//        Key zak = NameRegistrar.getIfExists("zak");
//        if (zak == null) {
//            try {
//
//                Key key = keyStore.getKey("ZAK", null);
//                if (provider.equals("SunJCE")) {
//                    zak = new SecretKeySpec(key.getEncoded(), key.getAlgorithm());
//                    NameRegistrar.register("zak", zak);
//                } else {
//                    NameRegistrar.register("zak", key);
//                }
//                log.info("Retrieve ZAK from CloudHSM: {}", key);
//                return key;
//            } catch (Exception ex) {
//                throw new CloudHsmException(ex);
//            }
//        }
//        log.info("ZAK from NameRegistrar: {}", zak);
//        return zak;
//
//    }

    public Key getZak() {
        return getZakWithoutCache();
    }

    public Key getZakWithoutCache() {
        try {
            return keyStore.getKey("ZAK", null);
        } catch (Exception ex) {
            throw new CloudHsmException(ex);
        }
    }


    public byte[] genMac(Key macKey, byte[] macDataBytes) throws CloudHsmException {
        try {
            Mac mac = Mac.getInstance("HmacSHA512", provider);
            mac.init(macKey);
            byte[] macBytes = mac.doFinal(macDataBytes);
            return Arrays.copyOf(macBytes, 8);
        } catch (Exception ex) {
            throw new CloudHsmException(ex);
        }
    }


    public byte[] decrypt(String keyLabel, byte[] encryptedData) {
        try {
            Key key = keyStore.getKey(keyLabel, null);

            Cipher encCipher = Cipher.getInstance("DESede/ECB/NoPadding","Cavium");
            encCipher.init(Cipher.DECRYPT_MODE, key);
            encCipher.update(encryptedData);
            byte[] cleartext = encCipher.doFinal();
            return cleartext;
        } catch (Exception e) {
            log.error("decrypt", e);
        }
        return new byte[0];
    }


    public Key storeKey(String label, byte[] keyValue, boolean extractable) throws RuntimeException {
        try {
            Key key = keyStore.getKey(label, null);
            if (key != null) {
                Util.deleteKey((CaviumKey) key);
            }

            SecretKey secretKey = new SecretKeySpec(keyValue, "DESede");

            CaviumKeyGenAlgorithmParameterSpec spec = new CaviumKeyGenAlgorithmParameterSpec(label, extractable, true);

            CaviumDES3Key caviumDES3Key = (CaviumDES3Key) ImportKey.importKey(secretKey, spec);
            log.info("Store key: {}", caviumDES3Key);
            return caviumDES3Key;
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException | CFM2Exception | InvalidKeyException ex) {
            throw new RuntimeException(ex);
        }
    }

    public byte[] kcv(byte[] keyValue) {
        log.info("KCV: key value: {}", ISOUtil.hexString(keyValue));
        try {
            Key key = new SecretKeySpec(keyValue, "DESede");

            Cipher encCipher = Cipher.getInstance("DESede/ECB/NoPadding", "Cavium");
            encCipher.init(Cipher.ENCRYPT_MODE, key);
            encCipher.update(ISOUtil.hex2byte("000000000000000000000000000000000000000000000000"));
            byte[] encryptedData = encCipher.doFinal();
            return Arrays.copyOf(encryptedData, 2);
        } catch (Exception e) {
            log.error("kcv", e);
        }
        return new byte[0];
    }
}
