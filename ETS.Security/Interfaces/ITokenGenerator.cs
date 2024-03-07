using ETS.Security.DTOs;
using ETS.Security.Models;
using ETS.Security.Services.Authentication;
using System.Security.Claims;

namespace ETS.Security.Interfaces
{
    public interface ITokenGenerator
    {
        Task<string> GenerateAccessToken(User user);
        string GenerateRefreshToken(User user);
        Task<AuthenticatedUserResponse> RefreshAccessToken(TokenRequest tokenRequest);
        Task<AuthenticatedUserResponse> GenerateTokens(User user);
    }
}
