using Microsoft.AspNetCore.Identity;
using Org.BouncyCastle.Utilities;

namespace ETS.Security.Models
{
    public class User : IdentityUser<Guid>
    {
        
        public string? RefreshToken { get; set; }
        public long ExpirationTime { get; set; }
    }
}
