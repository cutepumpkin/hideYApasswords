using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
    /// <summary>
    /// By Hassan Zaidi
    /// </summary>
    public static class EncryptDecryptUtility
    {
        #region Methods

        /// <summary>
        /// By Hassan Zaidi
        /// </summary>
        /// <param name="toEncrypt"></param>
        /// <param name="key"></param>
        /// <param name="useHashing"></param>
        /// <returns></returns>
        public static string Encrypt(string toEncrypt, string key, bool useHashing)
        {
            byte[] keyArray;
            byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(toEncrypt);

            if (useHashing)
            {
                MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
                keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
            }
            else
                keyArray = UTF8Encoding.UTF8.GetBytes(key);

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = keyArray;
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = tdes.CreateEncryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }

        /// <summary>
        /// By Hassan Zaidi
        /// </summary>
        /// <param name="toEncode"></param>
        /// <returns></returns>
        public static string Encrypt(string toEncode)
        {
            var toEncodeAsBytes = Encoding.ASCII.GetBytes(toEncode);
            var returnValue = System.Convert.ToBase64String(toEncodeAsBytes);
            return returnValue;
        }

        /// <summary>
        /// This method takes string to decrypt with the password salt same as which you used to encrypt the string
        /// By Hassan Zaidi
        /// </summary>
        /// <param name="toDecrypt"></param>
        /// <param name="key"></param>
        /// <param name="useHashing"></param>
        /// <returns></returns>
        public static string Decrypt(string toDecrypt, string key, bool useHashing)
        {
            byte[] keyArray;
            byte[] toEncryptArray = Convert.FromBase64String(toDecrypt);

            if (useHashing)
            {
                MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
                keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
            }
            else
                keyArray = UTF8Encoding.UTF8.GetBytes(key);

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = keyArray;
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = tdes.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return UTF8Encoding.UTF8.GetString(resultArray);
        }

        /// <summary>
        /// This method takes the string and decrypt the string by the  text encoding
        /// By Hassan Zaidi
        /// </summary>
        /// <param name="encodeData"></param>
        /// <returns></returns>
        public static string Decrypt(string encodeData)
        {

            var encodeDataAsBytes = System.Convert.FromBase64String(encodeData);
            var returnValue = Encoding.ASCII.GetString(encodeDataAsBytes);
            return returnValue;
        }
        
        }
}
