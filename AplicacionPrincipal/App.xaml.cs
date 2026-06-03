using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using Newtonsoft.Json;
namespace AplicacionPrincipal
{
    /// <summary>
    /// Lógica de interacción para App.xaml
    /// </summary>
    public partial class App : Application
    {
        // Propiedad global para acceder a la config desde cualquier parte
        public static string Config { get; private set; }

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            try
            {
                // Inyectamos aquí tu lógica de Program.cs
                Config = LoadSecureConfiguration();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error crítico de seguridad: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown(); // Cerramos la app si la configuración falla
            }
        }

        private string LoadSecureConfiguration()
        {
            string binFilePath = "appsettings.bin";
            string jsonFilePath = "appsettings.json";
            string publicKeyPath = Path.Combine("Key", "public.xml");

            // Llave AES (debe ser la misma que usaste en el Firmador o un valor constante seguro)
            byte[] aesKey;
            using (var sha = SHA256.Create())
            {
                aesKey = sha.ComputeHash(Encoding.UTF8.GetBytes("Llave_Maestra_Local"));
            }
            byte[] aesIv = new byte[16];

            if (File.Exists(binFilePath))
            {
                byte[] encryptedBin = File.ReadAllBytes(binFilePath);
                return Encoding.UTF8.GetString(DecryptAes(encryptedBin, aesKey, aesIv));
            }
            else if (File.Exists(jsonFilePath))
            {
                //var jsonContent = File.ReadAllText(jsonFilePath);
                //var signedWrapper = JsonConvert.DeserializeObject<SignedConfigWrapper>(jsonContent);

                //byte[] payloadBytes = Convert.FromBase64String(signedWrapper.PayloadBase64);
                //byte[] signatureBytes = Convert.FromBase64String(signedWrapper.SignatureBase64);

                //// 1. Verificar firma
                //using (var rsa = RSA.Create())
                //{
                //    rsa.FromXmlString(File.ReadAllText(publicKeyPath));
                //    if (!rsa.VerifyData(payloadBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                //        throw new Exception("Firma digital inválida: el archivo ha sido manipulado.");
                //}

                //// 2. Cifrar y guardar BIN
                //byte[] encryptedData = EncryptAes(payloadBytes, aesKey, aesIv);
                //File.WriteAllBytes(binFilePath, encryptedData);

                //// 3. Borrar JSON
                //File.Delete(jsonFilePath);

                //return Encoding.UTF8.GetString(payloadBytes);

                var jsonContent = File.ReadAllText(jsonFilePath);
                var signedWrapper = JsonConvert.DeserializeObject<SignedConfigWrapper>(jsonContent);

                // payloadBytes es el binario cifrado que viene del firmador
                byte[] payloadBytes = Convert.FromBase64String(signedWrapper.PayloadBase64);
                byte[] signatureBytes = Convert.FromBase64String(signedWrapper.SignatureBase64);

                // 1. Verificar firma (Firmamos el binario cifrado, así que esto es correcto)
                using (var rsa = RSA.Create())
                {
                    rsa.FromXmlString(File.ReadAllText(publicKeyPath));
                    if (!rsa.VerifyData(payloadBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                        throw new Exception("Firma digital inválida: el archivo ha sido manipulado.");
                }

                // 2. Descifrar el payload para obtener el JSON plano
                byte[] decryptedJsonBytes = DecryptAes(payloadBytes, aesKey, aesIv);

                // 3. Guardar el BIN (el .bin es el archivo cifrado que guardaremos en disco)
                File.WriteAllBytes(binFilePath, payloadBytes); // Guardamos el binario cifrado tal cual llegó

                // 4. Borrar JSON
                File.Delete(jsonFilePath);

                // Retornamos el JSON plano para que la App lo use
                return Encoding.UTF8.GetString(decryptedJsonBytes);
            }

            throw new Exception("No se encontró ningún archivo de configuración válido.");
        }

        // Métodos auxiliares (Deben ir dentro de la clase App)
        private byte[] EncryptAes(byte[] data, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key; aes.IV = iv;
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }

        private byte[] DecryptAes(byte[] encryptedData, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key; aes.IV = iv;
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedData, 0, encryptedData.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }

        public class SignedConfigWrapper
        {
            public string PayloadBase64 { get; set; }
            public string SignatureBase64 { get; set; }
        }

    }
}