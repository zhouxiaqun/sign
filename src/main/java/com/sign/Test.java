package com.sign;

/**
 * Created by zhou on 2017/6/21.
 */
public class Test {

    public static void main(String[] args) throws Exception{
        String m = System.getProperty("user.dir");
        String path = m+"\\src\\main\\resources";
//        GenerateKeyByRSA.genKeyPair(path);

        System.out.println("--------------公钥加密私钥解密过程-------------------");
        String plainText="ihep_公钥加密私钥解密";
        //公钥加密过程
        byte[] cipherData=RSA.encryptByPub(RSA.loadPublicKeyByStr(RSA.loadPublicKeyByFile(path)),plainText.getBytes());
        String cipher=Base64.encode(cipherData);
        //私钥解密过程
        byte[] res=RSA.decryptByPri(RSA.loadPrivateKeyByStr(RSA.loadPrivateKeyByFile(path)), Base64.decode(cipher));
        String restr=new String(res);
        System.out.println("原文："+plainText);
        System.out.println("加密："+cipher);
        System.out.println("解密："+restr);
        System.out.println();

        System.out.println("--------------私钥加密公钥解密过程-------------------");
        plainText="ihep_私钥加密公钥解密";
        //私钥加密过程
        cipherData=RSA.encryptByPri(RSA.loadPrivateKeyByStr(RSA.loadPrivateKeyByFile(path)),plainText.getBytes());
        cipher=Base64.encode(cipherData);
        //公钥解密过程
        res=RSA.decryptByPub(RSA.loadPublicKeyByStr(RSA.loadPublicKeyByFile(path)), Base64.decode(cipher));
        restr=new String(res);
        System.out.println("原文："+plainText);
        System.out.println("加密："+cipher);
        System.out.println("解密："+restr);
        System.out.println();

        System.out.println("---------------私钥签名过程------------------");
        String content="ihep_这是用于签名的原始数据";
        String signstr=RSASignature.sign(content,RSA.loadPrivateKeyByFile(path),"UTF-8");
        System.out.println("签名原串："+content);
        System.out.println("签名串："+signstr);
        System.out.println();

        System.out.println("---------------公钥校验签名------------------");
        System.out.println("签名原串："+content);
        System.out.println("签名串："+signstr);

        System.out.println("验签结果："+RSASignature.doCheck(content, signstr, RSA.loadPublicKeyByFile(path),"UTF-8"));
        System.out.println();
    }
}
