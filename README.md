# Android Web3j OOM解决
在Android客户端使用Web3j创建钱包、导入钱包时都可能会产生OOM，相关issue在Github上已经有所提及：https://github.com/web3j/web3j/issues/299 。这个问题在Web3j 3.0版本是没有的，由于
新版的Web3j使用spongycastle库替换了lambdaworks库，虽然在效率上提升了速度，但存在Android端的兼容性问题。

本项目代码地址：https://github.com/uncleleonfan/WalletOOM.git

## 创建钱包OOM解决
在创建钱包时，如果创建一个Full Wallet，则会导致OOM：

    public void onCreateFullWallet(View view) {
        String filePath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/full";
        File file = new File(filePath);
        file.mkdirs();
        try {
            WalletUtils.generateFullNewWalletFile("a12345678", file);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (CipherException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

Log如下：

    "Caused by: java.lang.OutOfMemoryError: Failed to allocate a 1036 byte allocation with 16777216 free bytes and 48MB until OOM; failed due to fragmentation (required continguous free 16384 bytes for a new buffer where largest contiguous free 8192 bytes)",
    "\tat org.spongycastle.util.Arrays.clone(Arrays.java:602)",
    "\tat org.spongycastle.crypto.generators.SCrypt.SMix(SCrypt.java:126)",
    "\tat org.spongycastle.crypto.generators.SCrypt.MFcrypt(SCrypt.java:87)",
    "\tat org.spongycastle.crypto.generators.SCrypt.generate(SCrypt.java:66)",
    "\tat org.web3j.crypto.Wallet.generateDerivedScryptKey(Wallet.java:136)",
    "\tat org.web3j.crypto.Wallet.create(Wallet.java:74)",
    "\tat org.web3j.crypto.Wallet.createStandard(Wallet.java:93)",
    "\tat org.web3j.crypto.WalletUtils.generateWalletFile(WalletUtils.java:61)"

generateFullNewWalletFile里面会调用createStandard创建钱包，使用N_STANDARD，P_STANDARD来配置加密强度，直接影响需使用的内存大小，最终导致OOM的发生。

    public static WalletFile createStandard(String password, ECKeyPair ecKeyPair)
            throws CipherException {
        return create(password, ecKeyPair, N_STANDARD, P_STANDARD);
    }


解决方法非常简单，创建一个Light Wallet即可：

    public void onCreateLightWallet(View view) {
        String filePath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/light";
        File file = new File(filePath);
        file.mkdirs();
        try {
            WalletUtils.generateLightNewWalletFile("a12345678", file);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (CipherException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

generateLightNewWalletFile会调用createLight来创建一个轻钱包，使用N_LIGHT，P_LIGHT，他们在数值上相对较小，所以
不会OOM。

    public static WalletFile createLight(String password, ECKeyPair ecKeyPair)
            throws CipherException {
        return create(password, ecKeyPair, N_LIGHT, P_LIGHT);
    }

我们可以对比一下N_STANDARD和P_STANDARD， N_LIGHT和P_LIGHT的大小：

    private static final int N_LIGHT = 1 << 12;
    private static final int P_LIGHT = 6;

    private static final int N_STANDARD = 1 << 18;
    private static final int P_STANDARD = 1;
## 导入钱包OOM解决
当我们导入一个轻钱包时，不会产生OOM，但导入不是一个轻钱包时，则有可能产生OOM。例如，我们使用Imtoken创建一个钱包并导出Keystore，
Keystore如下：

    {"address":"9a2e2419f3af050d4730f80e7a65b9f8deb5e16f","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"eaccea79c27a91e307f24988186ef21a"},"ciphertext":"a163e532edf2d76beaee5c26fd2c2fab071a9cb37627aa185ac89e223e41ab97","kdf":"scrypt","kdfparams":{"dklen":32,"n":65536,"p":1,"r":8,"salt":"6a847392a029553f4152dea7bb0b6fb0ac9eec29f55e572fe94603182f5ed7f1"},"mac":"3fad2a31e18c611b10df84db9ae368ce2e189b5c35e9f111e40ca4b4bfb02491"},"id":"032c47c2-c7b7-46f8-a3f7-f526580f6f09","version":3}

可以看到，其中n为65536，p为1，而轻钱包的n为1<<12,即2的12次方，4096，所以这不是一个轻钱包。
我们将该Keystore作为一个json文件push到SD卡中，然后使用Web3j进行导入：

    public void onImportWallet(View view) {
        try {
            //需提前将assets目录下的keystore.json文件推送到手机SD里面
            String filePath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/keystore.json";
            File file = new File(filePath);
            WalletUtils.loadCredentials("a12345678", file);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CipherException e) {
            e.printStackTrace();
        }
    }

发现同样会OOM：

     Caused by: java.lang.OutOfMemoryError: Failed to allocate a 1036 byte allocation with 13588800 free bytes and 12MB until OOM; failed due to fragmentation (required continguous free 16384 bytes for a new buffer where largest contiguous free 12288 bytes)
        at org.spongycastle.util.Arrays.clone(Arrays.java:602)
        at org.spongycastle.crypto.generators.SCrypt.SMix(SCrypt.java:126)
        at org.spongycastle.crypto.generators.SCrypt.MFcrypt(SCrypt.java:87)
        at org.spongycastle.crypto.generators.SCrypt.generate(SCrypt.java:66)
        at org.web3j.crypto.Wallet.generateDerivedScryptKey(Wallet.java:136)
        at org.web3j.crypto.Wallet.decrypt(Wallet.java:214)
        at org.web3j.crypto.WalletUtils.loadCredentials(WalletUtils.java:112)

通过log可以看出来，这里和创建钱包的OOM是一样的，都是最后调用generateDerivedScryptKey后导致:

    private static byte[] generateDerivedScryptKey(
            byte[] password, byte[] salt, int n, int r, int p, int dkLen) throws CipherException {
        return SCrypt.generate(password, salt, n, r, p, dkLen);
    }
创建钱包可以创建一个轻钱包，导入钱包总不能让用户换一个轻钱包来导入吧。这里，我们只能还是换回lambda库来完成keystore的编解码,
即我们可以自己写一个generateDerivedScryptKey方法，将spongycastle的SCrypt换成lambda的SCrypt。我们使用MyWalletUtils和MyWallet
共同完成该任务。

    public void onImportWallet(View view) {
        try {
            //需提前将assets目录下的keystore.json文件推送到手机SD里面
            String filePath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/keystore.json";
            File file = new File(filePath);
            Credentials credentials = MyWalletUtils.loadCredentials("a12345678", file);
            Log.d(TAG, "address:" + credentials.getAddress());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CipherException e) {
            e.printStackTrace();
        }
    }

    public class MyWalletUtils {

        public static Credentials loadCredentials(String password, File source)
                throws IOException, CipherException {
            WalletFile walletFile = objectMapper.readValue(source, WalletFile.class);
            return Credentials.create(MyWallet.decrypt(password, walletFile));
        }
    }

    public class MyWallet {

        private static final int CURRENT_VERSION = 3;

        private static final String CIPHER = "aes-128-ctr";
        static final String AES_128_CTR = "pbkdf2";
        static final String SCRYPT = "scrypt";

        private static byte[] generateDerivedScryptKey(
                byte[] password, byte[] salt, int n, int r, int p, int dkLen)  {
            try {
                return SCrypt.scrypt(password, salt, n, r, p, dkLen);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

按照以上方法处理之后，就可以解决OOM，但是用户等待的时间会稍微长一点，另外，最好还是添加一下Android平台的libscrpt.so库，大家可在本项目的jniLibs中找到。




