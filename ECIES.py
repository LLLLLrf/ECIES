import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from ECC import EllipticCurve
import random

class ECC:
    def __init__(self, curve):
        self.curve = curve

    def key_generation(self):
        """
        ECC 密钥生成
        """
        d = random.randint(1, self.curve.n - 1)  # 私钥
        Q = self.curve.scalar_multiplication(d, self.curve.G)  # 公钥
        return d, Q

    def kdf(self, shared_secret):
        """
        密钥派生函数 (KDF)
        """
        shared_secret_bytes = str(shared_secret).encode()
        derived = hashlib.sha256(shared_secret_bytes).digest()
        return derived[:16], derived[16:]  # 分为两个对称密钥 K_e 和 K_m

    def encrypt(self, m, Q_B):
        """
        ECC 加密（ECIES）
        """
        k = random.randint(1, self.curve.n - 1)  # 随机数
        R = self.curve.scalar_multiplication(k, self.curve.G)  # 临时公钥
        S = self.curve.scalar_multiplication(k, Q_B)  # 共享密钥
        K_e, K_m = self.kdf(S)  # 派生对称密钥

        # 加密消息
        cipher = AES.new(K_e, AES.MODE_CBC)
        c = cipher.encrypt(pad(m.encode(), AES.block_size))
        iv = cipher.iv

        # 生成MAC
        t = hmac.new(K_m, iv + c, hashlib.sha256).digest()
        return (R, iv, c, t)

    def decrypt(self, R, iv, c, t, d_B):
        """
        ECC 解密（ECIES）
        """
        S = self.curve.scalar_multiplication(d_B, R)  # 共享密钥
        K_e, K_m = self.kdf(S)  # 派生对称密钥

        # 验证MAC
        expected_t = hmac.new(K_m, iv + c, hashlib.sha256).digest()
        if not hmac.compare_digest(t, expected_t):
            raise ValueError("MAC 验证失败")

        # 解密消息
        cipher = AES.new(K_e, AES.MODE_CBC, iv)
        m = unpad(cipher.decrypt(c), AES.block_size)
        return m.decode()

# 示例椭圆曲线参数
class Curve:
    def __init__(self, a, b, p, G, n):
        self.a = a
        self.b = b
        self.p = p
        self.G = G
        self.n = n

    def scalar_multiplication(self, k, P):
        # 标量乘法算法
        ecc = EllipticCurve(self.a, self.b, self.p)
        return ecc.scalar_multiplication(k, P)

# 示例运行
curve = Curve(a=2, b=3, p=97, G=(3, 6), n=5)  # 简化参数
ecc = ECC(curve)

# 密钥生成
private_key, public_key = ecc.key_generation()
print(f"私钥: {private_key}")
print(f"公钥: {public_key}")

# 加密
message = "Hello, ECC!"
ciphertext = ecc.encrypt(message, public_key)
print("加密结果:", ciphertext)

# 解密
decrypted_message = ecc.decrypt(*ciphertext, private_key)
print("解密结果:", decrypted_message)
