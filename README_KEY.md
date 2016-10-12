java.security.Key接口是所有具体key的顶层接口, 它定义了所有key的功能.


Objects of type java.security.Key, of which java.security.PublicKey, java.security.PrivateKey, 
and javax.crypto.SecretKey are subclasses, are opaque key objects, because you cannot tell how they are implemented. 
The underlying implementation is provider-dependent, and may be software or hardware based. Key factories allow providers 
to supply their own implementations of cryptographic keys.



每个key都有三个特征:
a.算法 - 密钥算法通常是一个加密算法或者非对称算法(例如AES, DSA或RSA), key要用在这些算法中. 以及相关算法(例如 MD5withRSA, SHA1withRSA等)
        getAlgorithm()

b.编码形式 - JVM外部使用key时, key的编码. Key会编码成标准形式(例如X.509或者PKCS8)
        getEncoded()

c.格式 - 编码的key的格式名称
        getFormat()


Key的获取方式通常包括KeyGenerator, KeyPairGenerator, certificates, key specifications(使用KeyFactory), 或者KeyStore.
也可以使用 KeyFactory 来解析一个编码的key, 也可以使用CertificateFactory解析certificates.

SecretKey   PrivateKey                  PublicKey
PBEKey      DHPrivateKey                DHPublicKey
            DSAPrivateKey               DSAPublicKey
            ECPrivateKey                ECPublicKey
            RSAMultiPrimePrivateKey     RSAPublicKey
            RSAPrivateCrtKey
            RSAPrivateKey

其中, PublicKey和PrivateKey是无状态接口.
KeyPair是存放公钥/私钥的容器



Key对象和KeySpec是密钥数据的两种展示. Cipher使用Key对象初始化加密算法, 但是key需要转化成多种可携带形式用于传输和存储.


KeyFactory和SecretKeyFactory类能够转换模糊key和透明key(比如: Keys和KeySpecs之间)


------------------------------------------------------------------------
KeySpec是一个接口
SecretKeySpec           DHPrivateKeySpec                    DHPublicKeySpec
EncodedKeySpec          DSAPrivateKeySpec                   DSAPublicKeySpec
PKCS8EncodedKeySpec     ECPrivateKeySpec                    ECPublicKeySpec
X509EncodedKeySpec      RSAMultiPrimePrivateCrtKeySpec      RSAPublicKeySpec
                        RSAPrivateCrtKeySpec
DESKeySpec              RSAPrivateKeySpec
DESedeKeySpec
PBEKeySpec


EncodedKeySpec是一个抽象类
byte[] getEncoded() // 返回编码的key
String getFormat()  // 返回编码格式名称

PKCS8EncodedKeySpec是EncodedKeySpec的子类, 代表PrivateKey的DER编码, 依据PKCS8标准.
     getEncoded() 返回PKCS8标准的二进制数组
     getFormat()  返回"PKCS#8"

X509EncodedKeySpec是EncodedKeySpec的子类, 代表publicKey的DER编码, 依据X.509标准.
     getEncoded() 返回按照X.509标准的二进制数组
     getFormat() 返回"X.509"
     
     
     
------------------------------------------------------------------------
Generator 和 Factory
Generator用于生成一个全新的对象, 根据参数生成全新的密钥.
Factory是把一个已存在的对象转成另一个类型的对象.


------------------------------------------------------------------------
The KeyFactory class is an engine class designed to perform conversions 
between opaque cryptographic Keys and key specifications (transparent representations of the underlying key material).

KeyFactory是双向的, 它允许从特定的 Key Spec(key material)转成一个opaque key, 也允许反向操作.

// 创建一个KeyFactory对象
KeyFactory.getInstance()

// 在KeySpec和KeyObject之间转换key
PublicKey generatePublic(KeySpec keySpec)
PrivateKey generatePrivate(KeySpec keySpec)

KeySpec getKeySpec(Key key, Class keySpec);


------------------------------------------------------------------------
SecretKeyFactory类
SecretKeyFactory只用于操作对称密钥，而KeyFactory用于操作公钥/私钥

byte[] keyData = {};
SecretKeySpec keySpec = new SecretKeySpec(keyData, "DES");

SecretKey key = SecretKeyFactory.generateSecret(keySpec);

KeySpec keySpec = SecretKeyFactory.getKeySpec(Key key, Class keySpec);


------------------------------------------------------------------------
KeyPairGenerator

// 创建一个KeyPairGenerator实例
KeyPairGenerator getInstance()

// 初始化 - 算法不相关的初始化
void initialize(int keysize, SecureRandom random);

// 初始化 - 算法不相关的初始化
void initialize(AlgorithmParameterSpec params, SecureRandom random)

// 生成一个KeyPair
KeyPair generateKeyPair()


------------------------------------------------------------------------
KeyGenerator
用于创建对称密钥

// 创建一个 KeyGenerator
KeyGenerator.getInstance()

// 初始化一个 KeyGenerator - 算法无关
void init(SecureRandom random)
void init(keysize)

// 初始化一个 KeyGenerator - 算法相关
void init(AlgorithmParameterSpec params);
init(AlgorithmParameterSpec params, SecureRandom random);

// 生成安全密钥
SecretKey generateKey();