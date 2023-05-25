

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string alphabet = "abcdefghijklmnopqrstuvwxyz";
        public int LetterIdx(char letter)
        {
            for (int i = 0; i < 26; i++)
            {
                if (letter == alphabet[i]) return i;
            }

            return -1;
        }
        public string Encrypt(string plainText, int key)
        {
            int Indx;
            string cypher = "";
            int Tt = plainText.Length;

            for (int i = 0; i < Tt; i++)
            {
                if (char.IsLetter(plainText[i]))
                {
                    Indx = ((key + LetterIdx(plainText[i])) % 26); 
                    cypher += char.ToUpper(alphabet[Indx]);
                }
                else
                {
                    cypher += plainText[i];
                }
            }

            return cypher;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            int Cl = cipherText.Length;
            int Index;
            string P = "";
            for (int i = 0; i < Cl; i++)
            {
                if (char.IsLetter(cipherText[i]))
                {
                    Index = ((LetterIdx(cipherText[i]) - key) % 26);
                    if (Index < 0)
                        Index += 26;
                    P += alphabet[Index];
                }
                else
                {
                    P += cipherText[i];
                }
            }

            return P;
        }
        public int Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
    }
}

