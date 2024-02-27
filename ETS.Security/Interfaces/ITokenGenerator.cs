using ETS.Security.Models;
using ETS.Security.Services.Authentication;
using System.Security.Claims;

namespace ETS.Security.Interfaces
{
    public interface ITokenGenerator
    {
        Task<string> GenerateAccessToken(User user);
        string GenerateRefreshToken(User user);
        Task<AuthenticatedUserResponse> RefreshAccessToken(string accessToken, string refreshToken);
    }
}
