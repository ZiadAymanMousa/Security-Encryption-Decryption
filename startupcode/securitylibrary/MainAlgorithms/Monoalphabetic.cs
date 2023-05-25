using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public Dictionary<char, char> KeyDictionary(string key, string Operation)
        {
            Dictionary<char, char> dic = new Dictionary<char, char>();
            Ceaser ceaser = new Ceaser();
            for (int i = 0; i < 26; i++)
            {
                if (Operation == "encrypt")
                    dic.Add(ceaser.alphabet[i], key[i]);
                else
                    dic.Add(key[i], ceaser.alphabet[i]);
            }
            return dic;
        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            Dictionary<char, char> keyTable = KeyDictionary(key, "decrypt");
            cipherText = cipherText.ToLower();
            int CTLength = cipherText.Length;
            string PT = "";
            for (int i = 0; i < CTLength; i++) 
            {
                if (char.IsLetter(cipherText[i]))
                    PT += keyTable[cipherText[i]];
                else
                    PT += cipherText[i];
            }
            return PT;
        }

        public string Encrypt(string plainText, string key)
        {
            Dictionary<char, char> keyTable = KeyDictionary(key, "encrypt");
            int PTLength = plainText.Length;
            string CT = "";
            for (int i = 0; i < PTLength; i++) 
            {
                if (char.IsLetter(plainText[i]))
                    CT += keyTable[plainText[i]];
                else
                    CT += plainText[i];
            }

            return CT.ToUpper();
        }

       
        public string AnalyseUsingCharFrequency(string cipher)
        {
            throw new NotImplementedException();
        }
    }
}
