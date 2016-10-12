https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html


1. Navigate to the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 6 download page.
2. download the archive jce_policy-6.zip.
3. Extract jce\local_policy.jar and jce\US_export_policy.jar from the archive to the folder %JAVA_HOME%\jre\lib\security, overwriting the files already present in the directory.


独立算法通过定义密码引擎(服务)来实现, 定义能够提供加密引擎的类. 这些类被成为"引擎"类, 例如: MessageDigest, Signature, KeyFactory, KeyPairGenerator 和 Cipher 类.

为了使用 JCA, 应用程序能够请求一个特定类型对象(比如 MessageDigest)和一个特定算法或者服务(比如 MD5 算法), 以及某个已安装的Provider. 比如
md = MessageDigest.getInstance("MD5");
md = MessageDigest.getInstance("MD5", "ProviderC");


========================================================================
引擎类和算法: 引擎类提供加密服务的接口, 和具体的加密算法或者provider无关.
a. 加密操作 (加密, 数字签名, 消息摘要等等)
b. 加密资料的生成器或者转换器 (密钥和算法参数)
c. 封装加密数据或者用于更高层抽象的对象 (keystore或者证书)

引擎类列表:
SecureRandom: 生成随机数或者伪随机数
MessageDigest: 计算消息摘要(哈希值), 提供加密消息算法(SHA-1或者MD5, MD5生成16字节摘要, SHA1生成20字节摘要)
Signature: 用密钥初始化，用于签名和验证数据
Cipher: 用密钥初始化, 用于加解密数据. 有多种算法: 
        1. 对称块加密算法 (AES, DES, DESede, Blowfish, IDEA)
        2. 流式加密(RC4)
        3. 非对称加密算法(RSA)
        4. 基于密码的加密算法(PBE)
MessageAuthenticCode(MAC): 类似于MessageDigest生成哈希值, 但是首先要用密钥初始化来保护消息完整性.
KeyFactory: 把模糊的Key类型加密密钥, 转成规范化的密钥, 反之亦然 (底层透明转换)
SecretKeyFactory: 把模糊的SecretKey类型加密密钥, 转成规范化的密钥, 反之亦然 (底层透明转换). SecretKeyFactory仅用于生成安全的对称密钥的特例化的KeyFactory.
KeyPairGenerator: 使用特定的算法, 生成新的加密密钥
KeyAgreement: 用于多方同意或者建立一个特定的Key, 用作特定加密操作
AlgorithmParameters: 用于为特定加密算法存储参数, 包括参数编码和解码
AlgorithmParameterGenerator: 针对特定算法产生一组AlgorithmParameters
KeyStore: 用于创建和管理一个KeyStore, KeyStore是一个密钥数据库. KeyStore中的私钥有一个相关的证书链, 用于认证相关的公钥. KeyStore包含来自信任实体的证书
CertificateFactory: 用于创建公钥证书和证书召回列表(CRLs)
CertPathBuilder: 用于构建证书链 (认证路径)
CertPathValidator: 用于验证证书链
CertStore: 用于从repository中接收 Certificates 和 CRLs

注意: Generator用于创建全新的内容, 而factory从existing material中创建对象



------------------------------------------------------------------------
MessageDigest: 
引擎类, 用于提供MD5和SHA-1安全消息摘要功能的引擎类. 输入任意长度的消息, 生成固定长度的消息(MD5生成16字节长消息, SHA-1生成20字节长消息)
一个摘要算法需要满足两点:
a. 很难通过计算找到两个哈希值一样的消息
b. 通过摘要无法恢复原来的消息

// 创建实例
MessageDigest.getInstance()

// 更新消息摘要实例
void update(byte input);
void update(byte[] input);
void update(byte[] input, int offset, int len);

// 计算摘要
byte[] digest();
byte[] digest(byte[] input);
int digest(byte[] buf, int offset, int len);

Note: 如果buffer中没有足够空间, 该方法会抛异常


------------------------------------------------------------------------
Signature:
引擎类, 用于提供诸如DSA或者RSAwithMD5数字签名功能的引擎类. 输入任意长度的消息和私钥, 生成相对短的(通常固定长度)的字符串, 叫做签名.

Signature对象使用私钥和signing初始化，然后提供待签名的数据. 当需要验证时, 创建另一个 Signature 对象, 并用verification和公钥来初始化，然后输入数据和该数据的签名.
"SHA1WithRSA"使用消息对象"SHA1"来压缩消息为20字节长, 然后再对这20字节做签名.

Signature对象是有模式的, 每个Signature对象只能处于一个状态: UNINITIALIZED, SIGN, VERIFY

// 创建实例
Signature.getInstance()

// 初始化成 SIGN 状态
final void initSign(PrivateKey privateKey);

// 初始化成 VERIFY 状态
final void initVerify(PublicKey publicKey);
final void initVerify(Certificate certificate);

// 签名
final void update(byte b);
... 
final byte[] sign();
Note: sign()操作会重置signature对象为刚调用 initSign 后的状态, 用户可以继续使用同一个privateKey签名其他消息.

// 验证
final void update(byte b); // update原消息
...
final boolean verify(byte[] signature) // signature是原消息的签名
Note: verify()操作会重置signature对象为刚调用 initVerify 后的状态, 用户可以继续使用同一个publicKey验证其他签名.

Alternatively, a new call can be made to initVerify specifying a different public key 
(to initialize the Signature object for verifying a signature from a different entity), 
or to initSign (to initialize the Signature object for generating a signature).


------------------------------------------------------------------------
Cipher类
Cipher类提供了加密和解密的功能.

对称VS非对称,  流VS块加密, 操作模式

Stream vs. Block Ciphers 
块加密每次要处理一整个块，如果数据长度不够一个块，数据必须被padded, padded发生在加密之前.
padding可以有应用程序来完成, 也可以在初始化cipher的时候使用padding类型,比如"PKCS5PADDING".
流加密每次处理一个很小的单元(1字节), 它允许cipher不需要padding来处理数据.

操作模式:
块加密中,第一个块需要一个初始向量(IV). IV必须是随机的，但是无需保密.


一些算法(AES和RSA)不要求密钥长度固定, 但是另一些算法(DES和3DES)要求密钥长度固定. 密钥长度越长，安全性越好; 但是考虑到安全与时间的平衡, 应该选择合适长度的密钥长度.

大多数算法使用二进制密钥，但是人类习惯于记忆字符型密钥, 字符型密钥容易遭受字典攻击. 有些协议(例如PBE, Password-Based Encryption)能够把字符型密钥转成强二进制密钥.
转换的过程混入了随机数(盐, salt)来增加密钥的随机性.


创建 Cipher 实例
Cipher.getInstance()创建Cipher实例, 这里不只提供算法名, 还需要提供'transformation'. 
transformation是描述操作的字符串，通常包括'算法名'; 也可能跟随 mode 和 padding scheme.

transformation的形式:
'algorithm/mode/padding' or 'algorithm'
'DES/CBC/PKCS5Padding' or 'DES'

建议提供完整的transformation, 包括算法、mode和padding. 如果不这样做, provider会使用默认的, 比如'DES/ECB/PKCS5Padding'

// 创建 Cipher 实例
Cipher.getInstance(ENCRYPT_MODE | DECRYPT_MODE | WRAP_MODE | UNWRAP_MODE);
WRAP_MODE: 把java.security.Key包装成字节流, key可以被转换.
UNWRAP_MODE: 把二进制的key转换成 java.security.Key 对象.

每个Cipher初始化方法都使用操作模式参数. 其他参数包括key或者包含key的证书, 算法参数(params), 或者一个随机数源(random)
void init(int optmode, Key key)
void init(int optmode, Certificate certificate)
void init(int optmode, Key key, SecureRandom random)
void init(int optmode, Key key, AlgorithmParameterSpec params)

如果Cipher对象需要参数(比如初始化向量)来初始化加密操作,  但是该参数并没有提供给init方法. Cipher底层实现会提供所需的参数, 无论是使用默认值还是随机数; 
但是如果Cipher对象初始为解密操作是需要参数，但是该参数没有提供给init方法, 则会抛InvalidKeyException或者InvalidAlgorithmParameterException异常.

用于加密的参数必须和用于解密的参数保持一致.

初始化一个cipher，它以前所有的状态都会失去; 初始化一个cipher, 相当于创建了一个cipher新实例并初始化它.

byte[] doFinal(byte[] input);

byte[] update(byte[] input);
byte[] doFinal();


// 管理算法参数
无论是显示传入的参数，还是init方法生成的，都可以通过 getParameters 方法来检索内部参数.
如果参数是一个初始向量(IV), 可以通过 getIV 方法来查看.