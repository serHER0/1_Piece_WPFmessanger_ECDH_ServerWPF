using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace ServerWPF
{
   class CryptographyClass
  {
            ECDiffieHellmanCng alice = new ECDiffieHellmanCng();
            public static byte[] alicePublicKey;
            public static byte[] sessKey;

            public void generate_PublicKey(out byte[] alicePublicKey, out byte[] alicePrivateKey)
            {
                alice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                alice.HashAlgorithm = CngAlgorithm.Sha256;
                alicePublicKey = alice.PublicKey.ToByteArray();
                alicePrivateKey = alice.Key.Export(CngKeyBlobFormat.EccPrivateBlob);

            }
            public byte[] Creating_SessionKey(byte[] bobPublicKey, byte[] alicePrivateKey)
            {
                using (ECDiffieHellmanCng cng = new ECDiffieHellmanCng(CngKey.Import(alicePrivateKey, CngKeyBlobFormat.EccPrivateBlob)))
                {
                    cng.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                    cng.HashAlgorithm = CngAlgorithm.Sha512;
                    sessKey = cng.DeriveKeyMaterial(CngKey.Import(bobPublicKey, CngKeyBlobFormat.EccPublicBlob));
                    return sessKey;
                }
            }

            public void EncryptMsg(byte[] Sess_key, string secretMessage, out byte[] encryptedMessage, out byte[] iv)
            {
                using (Aes aes = new AesCryptoServiceProvider())
                {

                    aes.Key = Sess_key;
                    iv = aes.IV;


                    using (MemoryStream ciphertext = new MemoryStream())
                    using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] plaintextMessage = Encoding.UTF8.GetBytes(secretMessage);
                        cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                        cs.Close();
                        encryptedMessage = ciphertext.ToArray();
                    }
                }
            }
            public void EncryptMsg(byte[] Sess_key, byte[] secretMessage, out byte[] encryptedMessage, out byte[] iv)
            {
                using (Aes aes = new AesCryptoServiceProvider())
                {

                    var md5 = MD5.Create();
                    byte[] hash = md5.ComputeHash((Sess_key));
                    aes.Key = hash;
                    iv = aes.IV;


                    using (MemoryStream ciphertext = new MemoryStream())
                    using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] plaintextMessage = secretMessage;
                        cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                        cs.Close();
                        encryptedMessage = ciphertext.ToArray();
                    }
                }
            }
            public void EncryptMsg_IV(byte[] Sess_key, byte[] secretMessage, out byte[] encryptedMessage, byte[] iv)
            {
                using (Aes aes = new AesCryptoServiceProvider())
                {

                    var md5 = MD5.Create();
                    byte[] hash = md5.ComputeHash((Sess_key));
                    aes.Key = hash;
                    aes.IV = iv;


                    using (MemoryStream ciphertext = new MemoryStream())
                    using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] plaintextMessage = secretMessage;
                        cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                        cs.Close();
                        encryptedMessage = ciphertext.ToArray();
                    }
                }
            }
            public void DecryptMsg(byte[] Sess_key, byte[] encryptedMessage, byte[] iv, out string message)
            {
                using (Aes aes = new AesCryptoServiceProvider())
                {
                    var md5 = MD5.Create();
                    byte[] hash = md5.ComputeHash((Sess_key));
                    aes.Key = hash;
                    aes.IV = iv;


                    using (MemoryStream plaintext = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                            cs.Close();
                            message = Encoding.UTF8.GetString(plaintext.ToArray());


                        }
                    }
                }
            }
            public void DecryptMsg(byte[] Sess_key, byte[] encryptedMessage, byte[] iv, out byte[] message)
            {
                using (Aes aes = new AesCryptoServiceProvider())
                {
                    var md5 = MD5.Create();
                    byte[] hash = md5.ComputeHash((Sess_key));
                    aes.Key = hash;
                    aes.IV = iv;


                    using (MemoryStream plaintext = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                            cs.Close();
                            message = plaintext.ToArray();


                        }
                    }
                }
            }
  }
}



