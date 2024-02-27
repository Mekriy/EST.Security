using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ETS.Security.Models;

namespace ETS.Security.DataAccess
{
    public class SecurityContext : IdentityDbContext<User, IdentityRole<Guid>, Guid>
    {
        public SecurityContext()
        {
            
        }
        public SecurityContext(DbContextOptions<SecurityContext> options) : base(options) { }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }
    }
}
