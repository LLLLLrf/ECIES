import random

def extended_gcd(a, b):
    """
    扩展欧几里得算法，用于计算模逆。
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, p):
    """
    计算 a 在模 p 下的逆元。
    """
    gcd, x, _ = extended_gcd(a, p)
    if gcd != 1:
        raise ValueError("模逆不存在")
    return x % p

class EllipticCurve:
    def __init__(self, a, b, p):
        """
        初始化椭圆曲线 y^2 = x^3 + ax + b (mod p)
        """
        self.a = a
        self.b = b
        self.p = p

        if (4 * a**3 + 27 * b**2) % p == 0:
            raise ValueError("参数导致奇异曲线")

    def is_on_curve(self, x, y):
        """
        检查点 (x, y) 是否在曲线上。
        """
        return (y**2 - (x**3 + self.a * x + self.b)) % self.p == 0

    def point_addition(self, P, Q):
        """
        点加法运算。
        """
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and y1 != y2:
            return None

        if x1 == x2:
            denom = 2 * y1 % self.p
            if denom == 0:
                raise ValueError("点加法失败：分母为零")
            m = (3 * x1**2 + self.a) * mod_inverse(denom, self.p) % self.p
        else:
            denom = (x2 - x1) % self.p
            if denom == 0:
                raise ValueError("点加法失败：分母为零")
            m = (y2 - y1) * mod_inverse(denom, self.p) % self.p

        x3 = (m**2 - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p

        return (x3, y3)


    def scalar_multiplication(self, k, P):
        """
        标量乘法运算 k * P。
        """
        result = None
        addend = P

        while k:
            if k & 1:
                result = self.point_addition(result, addend)

            addend = self.point_addition(addend, addend)
            k >>= 1

        return result

if __name__ == "__main__":

    # 示例参数
    a = 2
    b = 3
    p = 97
    curve = EllipticCurve(a, b, p)
    G = (3, 6)  # 基点
    n = 5       # 标量

    # 验证基点是否在曲线上
    assert curve.is_on_curve(*G), "基点不在曲线上"

    # 计算标量乘法
    result = curve.scalar_multiplication(n, G)
    print(f"{n} * {G} = {result}")

    # ECC 密钥生成
    private_key = random.randint(1, p - 1)
    public_key = curve.scalar_multiplication(private_key, G)
    print(f"私钥: {private_key}")
    print(f"公钥: {public_key}")
