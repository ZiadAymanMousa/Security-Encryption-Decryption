using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.RSA
{
    public class RSA
    {
        // Encrypt a message using RSA
        public int Encrypt(int p, int q, int M, int e)
        {
            // Calculate n
            int n = p * q;
            // Calculate C = M^e mod n
            int C = FastPowerModulo(M, e, n);
            return C;
        }

        // Decrypt a message using RSA
        public int Decrypt(int p, int q, int C, int e)
        {
            // Calculate n
            int n = p * q;
            // Calculate phi(n)
            int phiN = (p - 1) * (q - 1);
            // Calculate d, the multiplicative inverse of e modulo phi(n)
            int d = GetMultiplicativeInverse(e, phiN);
            // Calculate M = C^d mod n
            int M = FastPowerModulo(C, d, n);
            return M;
        }

        // Calculate a^b mod n efficiently using modular exponentiation
        private int FastPowerModulo(int a, int b, int n)
        {
            int result = 1;

            while (b > 0)
            {
                if (b % 2 == 1)
                    result = (int)((long)result * a % n);
                a = (int)((long)a * a % n);
                b /= 2;
            }

            return result;
        }

        // Calculate the multiplicative inverse of a modulo n using the extended Euclidean algorithm
        private int GetMultiplicativeInverse(int a, int n)
        {
            int t = 0, newt = 1;
            int r = n, newr = a;

            // Check that a and n are coprime
            int gcd = GCD(a, n);
            if (gcd != 1)
                throw new Exception("a is not invertible");

            while (newr != 0)
            {
                int quotient = r / newr;
                (t, newt) = (newt, t - quotient * newt);
                (r, newr) = (newr, r - quotient * newr);
            }

            // Ensure that the result is positive
            if (t < 0)
                t += n;

            return t;
        }

        // Calculate the greatest common divisor of a and b using the Euclidean algorithm
        private int GCD(int a, int b)
        {
            if (b == 0)
                return a;
            return GCD(b, a % b);
        }
    }
}