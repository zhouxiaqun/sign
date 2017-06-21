package com.sign;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by zhou on 2017/6/21.
 */
public class RSA {
    /**
     * 字节数据转字符串专用集合
     */
    private static final char[] HEX_CHAR = { '0', '1', '2', '3', '4', '5', '6',
            '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    /**
     * 公钥加密过程
     *
     * @param rsaPublicKey
     *            公钥
     * @param plainData
     *            明文数据
     * @return
     * @throws Exception
     *             加密过程中的异常信息
     */
    public static byte[] encryptByPub(RSAPublicKey rsaPublicKey, byte[] plainData) throws Exception {
        if (rsaPublicKey == null) {
            throw new Exception("加密公钥为空");
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
            byte[] output = cipher.doFinal(plainData);
            return output;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("解密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("密文数据已损坏");
        }
    }

    /**
     * 私钥加密过程
     *
     * @param rsaPrivateKey
     *            私钥
     * @param plainData
     *            明文数据
     * @return
     * @throws Exception
     *             加密过程中的异常信息
     */
    public static byte[] encryptByPri(RSAPrivateKey rsaPrivateKey, byte[] plainData) throws Exception {
        if (rsaPrivateKey == null) {
            throw new Exception("加密私钥为空");
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
            byte[] output = cipher.doFinal(plainData);
            return output;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("解密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("密文数据已损坏");
        }
    }

    /**
     * 公钥解密过程
     *
     * @param rsaPublicKey
     *            公钥
     * @param cipherData
     *            密文数据
     * @return 明文
     * @throws Exception
     *             解密过程中的异常信息
     */
    public static byte[] decryptByPub(RSAPublicKey rsaPublicKey, byte[] cipherData) throws Exception {
        if (rsaPublicKey == null) {
            throw new Exception("解密公钥为空");
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, rsaPublicKey);
            byte[] output = cipher.doFinal(cipherData);
            return output;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("解密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("密文数据已损坏");
        }
    }

    /**
     * 私钥解密过程
     *
     * @param rsaPrivateKey
     *            私钥
     * @param cipherData
     *            密文数据
     * @return 明文
     * @throws Exception
     *             解密过程中的异常信息
     */
    public static byte[] decryptByPri(RSAPrivateKey rsaPrivateKey, byte[] cipherData) throws Exception {
        if (rsaPrivateKey == null) {
            throw new Exception("解密私钥为空");
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            byte[] output = cipher.doFinal(cipherData);
            return output;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("解密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("密文数据已损坏");
        }
    }

    /**
     * 字节数据转十六进制字符串
     *
     * @param data
     *            输入数据
     * @return 十六进制内容
     */
    public static String byteArrayToString(byte[] data){
        StringBuilder sb = new StringBuilder();
        for(int i = 0;i<data.length;i++){
            // 取出字节的高四位 作为索引得到相应的十六进制标识符 注意无符号右移
            sb.append(HEX_CHAR[(data[i] & 0xf0) >>> 4]);
            // 取出字节的低四位 作为索引得到相应的十六进制标识符
            sb.append(HEX_CHAR[(data[i] & 0x0f)]);
            if(i<data.length-1){
                sb.append(' ');
            }
        }
        return sb.toString();
    }

    /**
     * 从文件中输入流中加载公钥
     *
     * @param path
     *            公钥输入流
     * @throws Exception
     *             加载公钥时产生的异常
     */
    public static String loadPublicKeyByFile(String path) throws Exception {
        try {
            BufferedReader br = new BufferedReader(new FileReader(path
                    + "\\publicKey.keystore"));
            String readLine = null;
            StringBuilder sb = new StringBuilder();
            while ((readLine = br.readLine()) != null) {
                sb.append(readLine);
            }
            br.close();
            return sb.toString();
        } catch (IOException e) {
            throw new Exception("公钥数据流读取错误");
        } catch (NullPointerException e) {
            throw new Exception("公钥输入流为空");
        }
    }

    /**
     * 从字符串中加载公钥
     *
     * @param publicKeyStr
     *            公钥数据字符串
     * @throws Exception
     *             加载公钥时产生的异常
     */
    public static RSAPublicKey loadPublicKeyByStr(String publicKeyStr)
            throws Exception {
        try {
            byte[] buffer = new BASE64Decoder().decodeBuffer(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("公钥非法");
        } catch (NullPointerException e) {
            throw new Exception("公钥数据为空");
        }
    }

    /**
     * 从文件中加载私钥
     *
     * @param path
     *            私钥文件名
     * @return 是否成功
     * @throws Exception
     */
    public static String loadPrivateKeyByFile(String path) throws Exception {
        try {
            BufferedReader br = new BufferedReader(new FileReader(path
                    + "\\privateKey.keystore"));
            String readLine = null;
            StringBuilder sb = new StringBuilder();
            while ((readLine = br.readLine()) != null) {
                sb.append(readLine);
            }
            br.close();
            return sb.toString();
        } catch (IOException e) {
            throw new Exception("私钥数据读取错误");
        } catch (NullPointerException e) {
            throw new Exception("私钥输入流为空");
        }
    }

    public static RSAPrivateKey loadPrivateKeyByStr(String privateKeyStr)
            throws Exception {
        try {
            byte[] buffer = new BASE64Decoder().decodeBuffer(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("私钥非法");
        } catch (NullPointerException e) {
            throw new Exception("私钥数据为空");
        }
    }

    public static void main(String[] args) {
        String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCHBlnm4zFnyAP8rTdbop3lWRoIl1kpffaZxrSc\n" +
                "HL9jMcpDTtHXgmJrBesUtKdNGX2k9rxk8M2TIrfW+FCLsu6wFVNFfHlm1ENCT2NBcPSFRnvPI0Zs\n" +
                "5uUkU7gGt1gPq86XA5TpucecWc6pgHwGjzlzK37frq3fWEA41aYmKw2c+QIDAQAB";
        String priKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIcGWebjMWfIA/ytN1uineVZGgiX\n" +
                "WSl99pnGtJwcv2MxykNO0deCYmsF6xS0p00ZfaT2vGTwzZMit9b4UIuy7rAVU0V8eWbUQ0JPY0Fw\n" +
                "9IVGe88jRmzm5SRTuAa3WA+rzpcDlOm5x5xZzqmAfAaPOXMrft+urd9YQDjVpiYrDZz5AgMBAAEC\n" +
                "gYBfU0CNHMB4gGEwNinq67eFf449mnw8Ks26aup/fFwx76jYNAE5oLdSz27Tw2aJrAFkQT1oFglM\n" +
                "Yype/hf/SGfxqdLdpwGE3WrkXT1PONVMyDS3M1Je16YCkKMksTisOgFRlenYWKjQhiv+xOHpBH4N\n" +
                "cJ6cvlOSf9ZkZgr3hnxmwQJBALxFrOCncdQhXrXAywydn1Zef+SRshjFJAshwhePiesezkh0ycKk\n" +
                "1JzPn3JTkt/V3EwwbEptDnV/IINlr3aUFr0CQQC3mQe5BEkm6KsNZcCFpSXTEbGOBKLY5gZ862b4\n" +
                "jAF6O3BXHU02GELRzCFxoyQKiI+kesBW0T6Nf0X6IEDIl9DtAkBrNKmaSv6wMkhB6oQ0rNR8U9cz\n" +
                "ihsFq8w4YoKo890u+x2veIEiysUefcNnUFuEBb0pzTD8uFjRYxBagd6GARFpAkBOpQ2q0kwnj5je\n" +
                "B00dsm1uaXDePdwn/viegBO+ufJUEqv/lPyjBGdzCPb2f4SLwo2NTkufpMgfwnoON8yoYGfNAkAh\n" +
                "B0jvRXLpph8iB0oeH1yvSfHTb5roYnrSxlR+s2ziNdlk8r7hygJlzl+shfAY7Wltz3LcQjptOVvS\n" +
                "5RCSaY40";
        String str = "ABC";
        String path = "C:\\zhou\\key";
        try {
            System.out.println(str.toString());
            byte[] epubData = encryptByPub(loadPublicKeyByStr(loadPublicKeyByFile(path)), str.getBytes());
            String str1 = new BASE64Encoder().encode(epubData);
            System.out.println(str1);
            byte[] dpriData = decryptByPri(loadPrivateKeyByStr(loadPrivateKeyByFile(path)), epubData);
            String str2 = new String(dpriData);
            System.out.println(str2);
            byte[] epriData = encryptByPri(loadPrivateKeyByStr(loadPrivateKeyByFile(path)), str.getBytes());
            String str3 = new BASE64Encoder().encode(epriData);
            System.out.println(str3);
            byte[] dpubData = decryptByPub(loadPublicKeyByStr(loadPublicKeyByFile(path)), epriData);
            String str4 = new String(dpubData);
            System.out.println(str4);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
