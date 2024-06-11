using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace OAuthServer;

public class DevKeys
{
    // ასიმეტრიული დაშიფვრისთვის, გვჭირდება `public/private key`-ები
    // ამ შემთხვეავში ეგენი ინახება `RSA`-ში.
    private RSA RsaKey { get; }
    
    /*
     * ენკაფსულაციას უკეთებს ჩვენს `RsaKey`-ს, წვდომას აძლეევს,მხოლოდ `public key`-ზე. 
     */
    public RsaSecurityKey RsaSecurityKey => new RsaSecurityKey(RsaKey);
    
    public DevKeys(IWebHostEnvironment env)
    {
        // შევქმნათ ახალი წყვილი
        RsaKey = RSA.Create();
        var path = Path.Combine(env.ContentRootPath, "crypto_key");
        // ვნახოთ თუ გვაქვს ესეთი ფაილი უკვე
        if (File.Exists(path))
        {
            // თუ გვაქვს ეს ფაილი, შევქმნათ აახალი წყვილი
            var rsaKey = RSA.Create();
            
            // გადავაწეროთ, ფაილში არსებული `private key` ჩვენს `rsaKey`-s
            // private key-ს.
            rsaKey.ImportRSAPrivateKey(File.ReadAllBytes(path),out _);
        }
        else
        {
            // თუ არ გვაქვს ეგ ფაილი, სადააც ვინახავთ `private key`-ს,
            // ამოვაგდოთ `rsakey`-დან და შევინახოთ.
            var privateKey = RsaKey.ExportRSAPrivateKey();
            File.WriteAllBytes(path, privateKey);
        }
    }
}