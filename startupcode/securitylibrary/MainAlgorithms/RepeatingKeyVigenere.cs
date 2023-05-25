using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            int clength = cipherText.Length;
            string plaintext = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            int temp = 0;
            while (key.Length != clength)
            {
                key += key[temp];
                temp++;
            }
            for (int i = 0; i < clength; i++)
            {
                plaintext = plaintext + alphabet[((alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(key[i])) + 26) % 26];

            }

            return plaintext;
            
        }

        public string Encrypt(string plainText, string key)
        {
            int temp = 0;
            int plength = plainText.Length;
            string ciphertext = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            while (key.Length != plainText.Length)
            {
                key = key + key[temp];
                temp++;
            }
            for (int i = 0; i < plength; i++)
            {
                ciphertext = ciphertext + alphabet[((alphabet.IndexOf(plainText[i]) + alphabet.IndexOf(key[i]))) % 26];

            }
            return ciphertext;
        }
        }
    }