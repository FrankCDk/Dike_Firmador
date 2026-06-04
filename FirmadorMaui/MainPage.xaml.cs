using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CommunityToolkit.Maui.Storage;

namespace FirmadorMaui
{
    public partial class MainPage : ContentPage
    {
        // Solo necesitamos las rutas seleccionadas por el usuario
        private string selectedKeyPath = "";
        private string selectedJsonPath = "";

        public MainPage() => InitializeComponent();

        private async void OnGenerateKeysClicked(object sender, EventArgs e)
        {
            using var rsa = RSA.Create(2048);

            // Generar contenido
            string privateKey = rsa.ToXmlString(true);
            string publicKey = rsa.ToXmlString(false);

            // Guardar Privada
            var privResult = await FileSaver.Default.SaveAsync("private.xml",
                new MemoryStream(Encoding.UTF8.GetBytes(privateKey)), CancellationToken.None);

            // Guardar Pública
            var pubResult = await FileSaver.Default.SaveAsync("public.xml",
                new MemoryStream(Encoding.UTF8.GetBytes(publicKey)), CancellationToken.None);

            if (privResult.IsSuccessful && pubResult.IsSuccessful)
            {
                await DisplayAlert("Éxito", "Llaves creadas y guardadas con éxito.", "OK");
            }
        }

        private async void OnSelectKeyClicked(object sender, EventArgs e)
        {
            var result = await FilePicker.Default.PickAsync();
            if (result != null)
            {
                selectedKeyPath = result.FullPath; // Asignamos a la variable correcta
                LblKeyPath.Text = $"Llave: {result.FileName}";
            }
        }

        private async void OnSelectJsonClicked(object sender, EventArgs e)
        {
            var result = await FilePicker.Default.PickAsync();
            if (result != null)
            {
                selectedJsonPath = result.FullPath;
                string content = File.ReadAllText(result.FullPath);
                EditorJsonPreview.Text = content;
            }
        }
        
        private async void OnSignJsonClicked(object sender, EventArgs e)
        {
            // Validación: Aseguramos que ambas rutas estén cargadas
            if (string.IsNullOrEmpty(selectedKeyPath) || string.IsNullOrEmpty(selectedJsonPath))
            {
                await DisplayAlert("Error", "Debes seleccionar la llave privada Y el JSON.", "OK");
                return;
            }

            try
            {
                // 1. Cargar datos y cifrar
                byte[] rawData = File.ReadAllBytes(selectedJsonPath);
                byte[] aesKey = SHA256.HashData(Encoding.UTF8.GetBytes("Llave_Maestra_Local"));
                byte[] aesIv = new byte[16];
                byte[] encryptedData = EncryptAes(rawData, aesKey, aesIv);

                // 2. Cargar la llave privada
                using var rsa = RSA.Create();
                string keyXml = File.ReadAllText(selectedKeyPath);
                rsa.FromXmlString(keyXml);

                // 3. Firmar el bloque cifrado
                byte[] signature = rsa.SignData(encryptedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                // 4. Crear el JSON
                var signedData = new
                {
                    PayloadBase64 = Convert.ToBase64String(encryptedData),
                    SignatureBase64 = Convert.ToBase64String(signature)
                };

                string output = JsonSerializer.Serialize(signedData, new JsonSerializerOptions { WriteIndented = true });

                // 5. NUEVA OPCIÓN: Elegir dónde guardar el archivo
                var fileName = $"appsettings_{DateTime.Now:yyyyMMdd_HHmm}.json";

                using var stream = new MemoryStream(Encoding.UTF8.GetBytes(output));

                var fileSaverResult = await FileSaver.Default.SaveAsync(fileName, stream, CancellationToken.None);

                if (fileSaverResult.IsSuccessful)
                {
                    await DisplayAlert("Éxito", $"Archivo guardado en:\n{fileSaverResult.FilePath}", "OK");
                }
                else
                {
                    await DisplayAlert("Información", "El guardado fue cancelado.", "OK");
                }
            }
            catch (Exception ex)
            {
                await DisplayAlert("Error Crítico", ex.Message, "OK");
            }
        }

        private byte[] EncryptAes(byte[] data, byte[] key, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.Key = key; aes.IV = iv;
            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
            return ms.ToArray();
        }
    }
}
