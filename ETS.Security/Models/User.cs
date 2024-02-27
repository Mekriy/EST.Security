using Microsoft.AspNetCore.Identity;

namespace ETS.Security.Models
{
    public class User : IdentityUser<Guid>
    {
        public string RefreshToken { get; internal set; }
    }
}
