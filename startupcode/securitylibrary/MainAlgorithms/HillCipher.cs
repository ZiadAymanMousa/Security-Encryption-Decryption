﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using MathNet.Numerics.LinearAlgebra;
using MathNet.Numerics.LinearAlgebra.Double;

namespace SecurityLibrary
{
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public int det(Matrix<double> M)
        {
            double A = M[0, 0] * (M[1, 1] * M[2, 2] - M[1, 2] * M[2, 1]) -
                       M[0, 1] * (M[1, 0] * M[2, 2] - M[1, 2] * M[2, 0]) +
                       M[0, 2] * (M[1, 0] * M[2, 1] - M[1, 1] * M[2, 0]);
            int AI = (int)A % 26 >= 0 ? (int)A % 26 : (int)A % 26 + 26;
            for (int i = 0; i < 26; i++)
            {
                if (AI * i % 26 == 1)
                {
                    return i;
                }
            }

            return -1;

        }
        public Matrix<double> ModMinorCofactor(Matrix<double> M, int A)
        {
            Matrix<double> resMat = DenseMatrix.Create(3, 3, 0.0);
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    int x = i == 0 ? 1 : 0, y = j == 0 ? 1 : 0, x1 = i == 2 ? 1 : 2, y1 = j == 2 ? 1 : 2;
                    double r = ((M[x, y] * M[x1, y1] - M[x, y1] * M[x1, y]) * Math.Pow(-1, i + j) * A) % 26;
                    resMat[i, j] = r >= 0 ? r : r + 26;
                }
            }
            return resMat;
        }
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<double> keyD = key.ConvertAll(x => (double)x);
            List<double> CD = cipherText.ConvertAll(x => (double)x);
            int m = Convert.ToInt32(Math.Sqrt((key.Count)));
            Matrix<double> keyMatrix = DenseMatrix.OfColumnMajor(m, (int)key.Count / m, keyD.AsEnumerable());
            Matrix<double> PMatrix = DenseMatrix.OfColumnMajor(m, (int)cipherText.Count / m, CD.AsEnumerable());
            List<int> finalRes = new List<int>();
            if (keyMatrix.ColumnCount == 3)
            {
                keyMatrix = ModMinorCofactor(keyMatrix.Transpose(), det(keyMatrix));
            }
            else
            {
                keyMatrix = keyMatrix.Inverse();
                Console.WriteLine(keyMatrix.ToString());
                Console.WriteLine(((int)keyMatrix[0, 0]).ToString() + ", " + ((int)keyMatrix[0, 0]).ToString());

            }
            if (Math.Abs((int)keyMatrix[0, 0]).ToString() != Math.Abs((double)keyMatrix[0, 0]).ToString())
            {
                throw new SystemException();
            }
            for (int i = 0; i < PMatrix.ColumnCount; i++)
            {
                List<double> Res = new List<double>();
                Res = ((((PMatrix.Column(i)).ToRowMatrix() * keyMatrix) % 26).Enumerate().ToList());
                for (int j = 0; j < Res.Count; j++)
                {
                    int x = (int)Res[j] >= 0 ? (int)Res[j] : (int)Res[j] + 26;
                    finalRes.Add(x);
                }
            }

            for (int i = 0; i < finalRes.Count; i++)
            {
                Console.WriteLine(finalRes[i].ToString());
            }

            return finalRes;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<double> keyD = key.ConvertAll(x => (double)x);
            List<double> PD = plainText.ConvertAll(x => (double)x);
            int m = Convert.ToInt32(Math.Sqrt((key.Count)));
            Matrix<double> keyMatrix = DenseMatrix.OfColumnMajor(m, (int)key.Count / m, keyD.AsEnumerable());
            Matrix<double> PMatrix = DenseMatrix.OfColumnMajor(m, (int)plainText.Count / m, PD.AsEnumerable());
            List<int> finalRes = new List<int>();
            for (int i = 0; i < PMatrix.ColumnCount; i++)
            {
                List<double> Res = new List<double>();
                Res = ((((PMatrix.Column(i)).ToRowMatrix() * keyMatrix) % 26).Enumerate().ToList());
                for (int j = 0; j < Res.Count; j++)
                {
                    finalRes.Add((int)Res[j]);
                }
            }

            return finalRes;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
