using ETS.Security.DataAccess;

namespace ETS.Security.Services
{
    public class UserService
    {
        private readonly SecurityContext _securityContext;

        public UserService(SecurityContext securityContext)
        {
            _securityContext = securityContext;
        }

    }
}
