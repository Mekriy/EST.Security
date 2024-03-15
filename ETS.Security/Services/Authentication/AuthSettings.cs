using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace ETS.Security.Services.Authentication
{
    public class AuthSettings
    {
        public string SecretKey { get; set; }
        public double AccessTokenExpirationMinutes { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public int RefreshTokenExpirationDays { get; set; }

        public SecurityKey GetSecretKey()
        {
            return new SymmetricSecurityKey(Encoding.ASCII.GetBytes(SecretKey));
        }
    }
}
