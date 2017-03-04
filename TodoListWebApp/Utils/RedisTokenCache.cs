using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using StackExchange.Redis;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Security;

namespace TodoListWebApp.Utils
{
    // https://github.com/mrochon/RedisTokenCache/blob/master/RedisTokenCacheSample/Cache/RedisTokenCache.cs
    public class RedisTokenCache : TokenCache
    {
        private string UserId;
        private UserTokenCacheItem Cache;
        private string cacheId = string.Empty;
        private const string MachineKeyPurpose = "TodoListWebApp:Username:{0}";
        private const string Anonymous = "<anonymous>";
        private static string localVector = AesManagedCryptoLib.GenerateRandomIV(16); //16 bytes = 128 bits
        private static string encryptionKey = AesManagedCryptoLib.getHashSha256("my secret key", 31); //32 bytes = 256 bits

        public RedisTokenCache(string signedInUserId)
        {
            // associate the cache to the current user of the web app
            UserId = signedInUserId;
            cacheId = UserId + "_TokenCache";
            this.AfterAccess = AfterAccessNotification;
            this.BeforeAccess = BeforeAccessNotification;
            this.BeforeWrite = BeforeWriteNotification;
            Load();
        }

        private string GetMachineKeyPurpose()
        {
            return String.Format(MachineKeyPurpose, UserId);
        }

        private string GetMachineKeyPurpose(IPrincipal user)
        {
            return String.Format(MachineKeyPurpose,
                user.Identity.IsAuthenticated ? user.Identity.Name : Anonymous);
        }

        public void Load()
        {
            // look up the entry in the cache
            var cache = Redis.Connection.GetDatabase();
            try
            {
                var cachedItem = cache.StringGet(cacheId);
                if (cachedItem.HasValue)
                {
                    this.Cache = JsonConvert.DeserializeObject<UserTokenCacheItem>(cachedItem);
                    // ToDo: if the entry in Redis cache is older than 1 hour which is the default validity of AAD access token then kill it.
                    //var purpose = GetMachineKeyPurpose(Thread.CurrentPrincipal);
                    var purpose = GetMachineKeyPurpose();
                    //this.Deserialize((this.Cache == null) ? null : MachineKey.Unprotect(this.Cache.cacheBits, purpose));
                    //this.Deserialize((this.Cache == null) ? null : AesEncryptionHelper.Decrypt(this.Cache.cacheBits, purpose));
                    AesManagedCryptoLib _crypt = new AesManagedCryptoLib();
                    //this.Deserialize((this.Cache == null) ? null : _crypt.decrypt(this.Cache.CacheBits, purpose, localVector));
                    this.Deserialize((this.Cache == null) ? null : _crypt.decrypt(this.Cache.CacheBits, purpose, this.Cache.InitializationVector));
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception in RedisTokenCache(id): " + ex.Message);
                Cache = null;
            }
        }

        // clean up the database
        public override void Clear()
        {
            base.Clear();
            try
            {
                var cache = Redis.Connection.GetDatabase();
                cache.KeyDelete(cacheId);
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception in RedisTokenCache.Clear: " + ex.Message);
            }
        }

        // Notification raised before ADAL accesses the cache.
        // This is your chance to update the in-memory copy from the cache, if the in-memory version is stale
        void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            try
            {
                var cache = Redis.Connection.GetDatabase();
                var cachedItem = cache.StringGet(cacheId);
                if (cachedItem.HasValue)
                {
                    var status = JsonConvert.DeserializeObject<UserTokenCacheItem>(cachedItem);
                    if ((this.Cache != null) && (status.LastWrite > this.Cache.LastWrite))
                    {
                        this.Cache = status;
                        //var purpose = GetMachineKeyPurpose(Thread.CurrentPrincipal);
                        var purpose = GetMachineKeyPurpose();
                        //this.Deserialize((Cache == null) ? null : MachineKey.Unprotect(Cache.cacheBits, purpose));
                        //this.Deserialize((Cache == null) ? null : AesEncryptionHelper.Decrypt(Cache.cacheBits, purpose));
                        AesManagedCryptoLib _crypt = new AesManagedCryptoLib();
                        //this.Deserialize((this.Cache == null) ? null : _crypt.decrypt(this.Cache.CacheBits, purpose, localVector));
                        this.Deserialize((this.Cache == null) ? null : _crypt.decrypt(this.Cache.CacheBits, purpose, this.Cache.InitializationVector));
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception in RedisTokenCache.BeforeAccessNotification: " + ex.Message);
            }
        }

        // Notification raised after ADAL accessed the cache.
        // If the HasStateChanged flag is set, ADAL changed the content of the cache
        void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if state changed
            if (this.HasStateChanged)
            {
                //var purpose = GetMachineKeyPurpose(Thread.CurrentPrincipal);
                var purpose = GetMachineKeyPurpose();
                AesManagedCryptoLib _crypt = new AesManagedCryptoLib();
                string dynamicVector = AesManagedCryptoLib.GenerateRandomIV(16); //16 bytes = 128 bits
                Cache = new UserTokenCacheItem
                {
                    //cacheBits = MachineKey.Protect(this.Serialize(), purpose),
                    //cacheBits = AesEncryptionHelper.Encrypt(this.Serialize(), purpose),
                    //cacheBits = cryptoHelper.Encrypt(this.Serialize()),
                    //CacheBits = _crypt.encrypt(this.Serialize(), purpose, localVector),
                    CacheBits = _crypt.encrypt(this.Serialize(), purpose, dynamicVector),
                    InitializationVector = dynamicVector,
                    LastWrite = DateTime.Now.ToUniversalTime()
                };

                try
                {
                    var cache = Redis.Connection.GetDatabase();
                    var cacheItemJson = JsonConvert.SerializeObject(Cache);
                    cache.StringSet(cacheId, cacheItemJson, TimeSpan.FromDays(1)); // could we use token expiry somehow?
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("Exception in RedisTokenCache.AfterAccessNotification: " + ex.Message);
                }
                this.HasStateChanged = false;
            }
        }

        void BeforeWriteNotification(TokenCacheNotificationArgs args)
        {
            // if you want to ensure that no concurrent write take place, use this notification to place a lock on the entry
        }

        public override void DeleteItem(TokenCacheItem item)
        {
            base.DeleteItem(item);
            try
            {
                var cache = Redis.Connection.GetDatabase();
                var cachedItem = cache.KeyDelete(cacheId);
            }
            catch (Exception ex)
            {
                Trace.WriteLine("Exception in RedisTokenCache.DeleteItem: " + ex.Message);
            }
        }
    }

    /// <summary>
    /// A simple wrapper to the AesManaged class and the AES algorithm.
    /// Requires a securely stored key which should be a random string of characters that an attacker could never guess.
    /// </summary>
    public class AesEncryptionHelper
    {
        private static readonly int _saltSize = 32;

        /// <summary>
        /// Encrypts the plainText input using the given Key.
        /// A 128 bit random salt will be generated and prepended to the ciphertext before it is base64 encoded.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="key">The plain text encryption key.</param>
        /// <returns>The salt and the ciphertext, Base64 encoded for convenience.</returns>
        public static string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException("plainText");
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("key");

            // Derive a new Salt and IV from the Key
            using (var keyDerivationFunction = new Rfc2898DeriveBytes(key, _saltSize))
            {
                var saltBytes = keyDerivationFunction.Salt;
                var keyBytes = keyDerivationFunction.GetBytes(32);
                var ivBytes = keyDerivationFunction.GetBytes(16);

                // Create an encryptor to perform the stream transform.
                // Create the streams used for encryption.
                using (var aesManaged = new AesManaged())
                using (var encryptor = aesManaged.CreateEncryptor(keyBytes, ivBytes))
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    using (var streamWriter = new StreamWriter(cryptoStream))
                    {
                        // Send the data through the StreamWriter, through the CryptoStream, to the underlying MemoryStream
                        streamWriter.Write(plainText);
                    }

                    // Return the encrypted bytes from the memory stream, in Base64 form so we can send it right to a database (if we want).
                    var cipherTextBytes = memoryStream.ToArray();
                    Array.Resize(ref saltBytes, saltBytes.Length + cipherTextBytes.Length);
                    Array.Copy(cipherTextBytes, 0, saltBytes, _saltSize, cipherTextBytes.Length);

                    return Convert.ToBase64String(saltBytes);
                }
            }
        }

        public static byte[] Encrypt(byte[] plainText, string key)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("key");

            // Derive a new Salt and IV from the Key
            using (var keyDerivationFunction = new Rfc2898DeriveBytes(key, _saltSize))
            {
                var saltBytes = keyDerivationFunction.Salt;
                var keyBytes = keyDerivationFunction.GetBytes(32);
                var ivBytes = keyDerivationFunction.GetBytes(16);

                // Create an encryptor to perform the stream transform.
                // Create the streams used for encryption.
                using (var aesManaged = new AesManaged())
                using (var encryptor = aesManaged.CreateEncryptor(keyBytes, ivBytes))
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    using (var streamWriter = new StreamWriter(cryptoStream))
                    {
                        // Send the data through the StreamWriter, through the CryptoStream, to the underlying MemoryStream
                        streamWriter.Write(plainText);
                    }

                    // Return the encrypted bytes from the memory stream.
                    var cipherTextBytes = memoryStream.ToArray();
                    Array.Resize(ref saltBytes, saltBytes.Length + cipherTextBytes.Length);
                    Array.Copy(cipherTextBytes, 0, saltBytes, _saltSize, cipherTextBytes.Length);

                    return saltBytes;
                }
            }
        }

        /// <summary>
        /// Decrypts the ciphertext using the Key.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="key">The plain text encryption key.</param>
        /// <returns>The decrypted text.</returns>
        public static string Decrypt(string ciphertext, string key)
        {
            if (string.IsNullOrEmpty(ciphertext))
                throw new ArgumentNullException("cipherText");
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("key");

            // Extract the salt from our ciphertext
            var allTheBytes = Convert.FromBase64String(ciphertext);
            var saltBytes = allTheBytes.Take(_saltSize).ToArray();
            var ciphertextBytes = allTheBytes.Skip(_saltSize).Take(allTheBytes.Length - _saltSize).ToArray();

            using (var keyDerivationFunction = new Rfc2898DeriveBytes(key, saltBytes))
            {
                // Derive the previous IV from the Key and Salt
                var keyBytes = keyDerivationFunction.GetBytes(32);
                var ivBytes = keyDerivationFunction.GetBytes(16);

                // Create a decrytor to perform the stream transform.
                // Create the streams used for decryption.
                // The default Cipher Mode is CBC and the Padding is PKCS7 which are both good
                using (var aesManaged = new AesManaged())
                using (var decryptor = aesManaged.CreateDecryptor(keyBytes, ivBytes))
                using (var memoryStream = new MemoryStream(ciphertextBytes))
                using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                using (var streamReader = new StreamReader(cryptoStream))
                {
                    // Return the decrypted bytes from the decrypting stream.
                    return streamReader.ReadToEnd();
                }
            }
        }

        public static byte[] Decrypt(byte[] ciphertext, string key)
        {
            if (ciphertext == null || ciphertext.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("key");

            // Extract the salt from our ciphertext
            var allTheBytes = ciphertext;
            var saltBytes = allTheBytes.Take(_saltSize).ToArray();
            var ciphertextBytes = allTheBytes.Skip(_saltSize).Take(allTheBytes.Length - _saltSize).ToArray();

            using (var keyDerivationFunction = new Rfc2898DeriveBytes(key, saltBytes))
            {
                // Derive the previous IV from the Key and Salt
                var keyBytes = keyDerivationFunction.GetBytes(32);
                var ivBytes = keyDerivationFunction.GetBytes(16);

                // Create a decrytor to perform the stream transform.
                // Create the streams used for decryption.
                // The default Cipher Mode is CBC and the Padding is PKCS7 which are both good
                using (var aesManaged = new AesManaged())
                using (var decryptor = aesManaged.CreateDecryptor(keyBytes, ivBytes))
                using (var memoryStream = new MemoryStream(ciphertextBytes))
                using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                using (var streamReader = new StreamReader(cryptoStream))
                {
                    // Return the decrypted bytes from the decrypting stream.
                    string s = streamReader.ReadToEnd();
                    return Convert.FromBase64String(s);
                }
                
                var aesManaged1 = new AesManaged();
                aesManaged1.Key = keyBytes;
                aesManaged1.IV = ivBytes;
                byte[] plainText = aesManaged1.CreateDecryptor().TransformFinalBlock(ciphertextBytes, 0, ciphertextBytes.Length);
            }
        }
    }

    public class AESHelper : IDisposable
    {
        public AesManaged AESManaged;
        internal ICryptoTransform Encryptor { get; set; }
        internal ICryptoTransform Decryptor { get; set; }
        private const string KEY = "2428GD19569F9B2C2341839416C8E87G";
        private static readonly byte[] Salt = Encoding.ASCII.GetBytes("?pt1$8f]l4g80");
        private const Int32 ITERATIONS = 1042;


        internal AESHelper()
        {
            AESManaged = new AesManaged();
            AESManaged.BlockSize = AESManaged.LegalBlockSizes[0].MaxSize;
            AESManaged.KeySize = AESManaged.LegalKeySizes[0].MaxSize;
            AESManaged.Mode = CipherMode.CBC;
        }
        public void KeyGenerator()
        {
            var key = new Rfc2898DeriveBytes(KEY, Salt, ITERATIONS);
            AESManaged.Key = key.GetBytes(AESManaged.KeySize / 8);
        }
        public byte[] Encrypt(byte[] input)
        {
            KeyGenerator();
            var ms = new MemoryStream();
            //Random IV 
            Encryptor = AESManaged.CreateEncryptor(AESManaged.Key, AESManaged.IV);
            //Add the IV to the beginning of the memory stream
            ms.Write(BitConverter.GetBytes(AESManaged.IV.Length), 0, sizeof(int));
            ms.Write(AESManaged.IV, 0, AESManaged.IV.Length);
            var cs = new CryptoStream(ms, Encryptor, CryptoStreamMode.Write);
            cs.Write(input, 0, input.Length);
            cs.Close();
            return ms.ToArray();
        }
        public byte[] Decrypt(byte[] input)
        {
            KeyGenerator();

            // Get the initialization vector from the encrypted stream
            var ms = new MemoryStream(input);
            AESManaged.IV = ReadByteArray(ms);
            Decryptor = AESManaged.CreateDecryptor(AESManaged.Key, AESManaged.IV);
            var cs = new CryptoStream(ms, Decryptor, CryptoStreamMode.Write);
            cs.Write(input, 0, input.Length);
            
            var allTheBytes = input;
            var saltBytes = allTheBytes.Take(16).ToArray();
            var ciphertextBytes = allTheBytes.Skip(16).Take(allTheBytes.Length - 16).ToArray();

            cs.Write(ciphertextBytes, 0, ciphertextBytes.Length);
            cs.Close();//Error occurs here
            return ms.ToArray();
        }

        private static byte[] ReadByteArray(Stream s)
        {
            var rawLength = new byte[sizeof(int)];
            if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array");
            }
            var buffer = new byte[16];
            if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
            {
                throw new SystemException("Did not read byte array properly");
            }

            return buffer;
        }
        private static byte[] StreamToByteArray(Stream inputStream)
        {
            if (!inputStream.CanRead)
            {
                throw new ArgumentException();
            }

            // This is optional
            if (inputStream.CanSeek)
            {
                inputStream.Seek(0, SeekOrigin.Begin);
            }

            var output = new byte[inputStream.Length];
            var bytesRead = inputStream.Read(output, 0, output.Length);
            Debug.Assert(bytesRead == output.Length, "Bytes read from stream matches stream length");
            return output;
        }
        public void Dispose()
        {
            if (AESManaged != null)
                ((IDisposable)AESManaged).Dispose();

        }
    }

    public class Redis
    {
        //private static ConfigurationOptions _configurationOptions;
        //public Redis(ConfigurationOptions configurationOptions)
        //{
        //    if (configurationOptions == null) throw new ArgumentNullException("configurationOptions");

        //    _configurationOptions = configurationOptions;
        //}

        // Redis Connection string info
        private static Lazy<ConnectionMultiplexer> lazyConnection = new Lazy<ConnectionMultiplexer>(() =>
        {
            //return ConnectionMultiplexer.Connect(_configurationOptions);
            //string cacheConnection = ConfigurationManager.AppSettings["ida:CacheConnection"].ToString();


            string cacheConnection = String.Format("{0},password={1},ssl=True", 
                ConfigurationManager.AppSettings["ida:RedisEndpoint"].ToString(),
                ConfigurationManager.AppSettings["ida:RedisAccessKey"].ToString());
            return ConnectionMultiplexer.Connect(cacheConnection);
        });

        public static ConnectionMultiplexer Connection
        {
            get
            {
                return lazyConnection.Value;
            }
        }

        public static void Dispose()
        {
            Connection.Dispose();
        }
    }

    public class UserTokenCacheItem
    {
        public byte[] CacheBits { get; set; }

        /// <summary>
        ///     
        /// </summary>
        /// <seealso cref="https://en.wikipedia.org/wiki/Initialization_vector"/>
        public string InitializationVector { get; set; }

        public DateTime LastWrite { get; set; }
    }
}