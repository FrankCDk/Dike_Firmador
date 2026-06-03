using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FirmadorMaui
{
    public partial class MainPage : ContentPage
    {
        private string privateKeyPath = Path.Combine(FileSystem.AppDataDirectory, "private.xml");
        private string selectedJsonPath = "";

        public MainPage() => InitializeComponent();

        private void OnGenerateKeysClicked(object sender, EventArgs e)
        {
            using var rsa = RSA.Create(2048);

            // Guardar Privada (Para el Firmador)
            File.WriteAllText(privateKeyPath, rsa.ToXmlString(true));

            // Guardar Pública (Para la MainApp)
            string publicKeyPath = Path.Combine(FileSystem.AppDataDirectory, "public.xml");
            File.WriteAllText(publicKeyPath, rsa.ToXmlString(false)); // FALSE = Solo Pública

            LblKeyStatus.Text = $"Estado: Llaves creadas. Copia 'public.xml' a tu MainApp.";
        }

        private async void OnSelectJsonClicked(object sender, EventArgs e)
        {
            var result = await FilePicker.Default.PickAsync();
            if (result != null)
            {
                selectedJsonPath = result.FullPath;
                LblFileStatus.Text = $"Archivo: {result.FileName}";
            }
        }

        private async void OnSignJsonClicked(object sender, EventArgs e)
        {
            if (!File.Exists(privateKeyPath) || string.IsNullOrEmpty(selectedJsonPath))
            {
                await DisplayAlert("Error", "Genera las llaves y selecciona un JSON primero.", "OK");
                return;
            }

            // 1. Preparar datos y llave AES
            byte[] rawData = File.ReadAllBytes(selectedJsonPath);

            // IMPORTANTE: Esta misma cadena debe ser igual a la de tu MainApp
            byte[] aesKey = SHA256.HashData(Encoding.UTF8.GetBytes("Llave_Maestra_Local"));
            byte[] aesIv = new byte[16]; // Vector de inicialización (puedes usar este fijo)

            // 2. Cifrar los datos con AES
            byte[] encryptedData = EncryptAes(rawData, aesKey, aesIv);

            // 3. Cargar llave RSA para firmar los datos YA CIFRADOS
            using var rsa = RSA.Create();
            rsa.FromXmlString(File.ReadAllText(privateKeyPath));

            // 4. Firmar el bloque cifrado (es más seguro firmar el resultado cifrado)
            byte[] signature = rsa.SignData(encryptedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // 5. Crear el JSON firmado (ahora el Payload es el binario cifrado)
            var signedData = new
            {
                PayloadBase64 = Convert.ToBase64String(encryptedData),
                SignatureBase64 = Convert.ToBase64String(signature)
            };

            string output = JsonSerializer.Serialize(signedData, new JsonSerializerOptions { WriteIndented = true });

            // Guardar archivo
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmm");
            string fileName = $"appsettings_{timestamp}.json";
            string outputPath = Path.Combine(FileSystem.Current.AppDataDirectory, fileName);
            File.WriteAllText(outputPath, output);

            await DisplayAlert("Éxito", $"JSON firmado y cifrado guardado en:\n{outputPath}", "OK");

            // Abrir carpeta
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo()
            {
                FileName = FileSystem.AppDataDirectory,
                UseShellExecute = true,
                Verb = "open"
            });
        }

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
    }
}
