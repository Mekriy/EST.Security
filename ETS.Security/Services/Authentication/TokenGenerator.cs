using ETS.Security.DTOs;
using ETS.Security.Interfaces;
using ETS.Security.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using ETS.Security.DataAccess;
using ETS.Security.Helpers;
using Microsoft.EntityFrameworkCore;

namespace ETS.Security.Services.Authentication
{
    public class TokenGenerator : ITokenGenerator
    {
        private const int RefreshTokenSize = 32;
        private readonly UserManager<User> _userManager;
        private readonly AuthSettings _authSettings;
        private readonly SecurityContext _context;
        public TokenGenerator(UserManager<User> userManager, AuthSettings authSettings, SecurityContext context)
        {
            _userManager = userManager;
            _authSettings = authSettings;
            _context = context;
        }

        public async Task<string> GenerateAccessToken(User user)
        {
            var handler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_authSettings.SecretKey);
            var roles = await _userManager.GetRolesAsync(user);

            var identity = new ClaimsIdentity(new[] {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, roles.FirstOrDefault(ClaimTypes.Role))
            });

            var securityToken = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = _authSettings.Issuer,
                Audience = _authSettings.Audience,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Subject = identity,
                Expires = DateTime.Now.AddMinutes(_authSettings.AccessTokenExpirationMinutes)
            });
            return handler.WriteToken(securityToken);
        }

        public string GenerateRefreshToken(User user)
        {
            var randomNumber = new byte[RefreshTokenSize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
        public async Task<AuthenticatedUserResponse> GenerateTokens(User user)
        {
            user.RefreshToken = GenerateRefreshToken(user);
            user.ExpirationTime = DateTimeOffset.UtcNow.AddDays(_authSettings.RefreshTokenExpirationDays).ToUnixTimeSeconds();
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Error",
                    Detail = "Unable to create refresh token"
                }; 
            }
            return new AuthenticatedUserResponse
            {
                Access = await GenerateAccessToken(user),
                Refresh = user.RefreshToken,
            };
        }
        public async Task<AuthenticatedUserResponse> RefreshAccessToken(TokenRequest tokenRequest)
        {
            var principal = GetPrincipalFromExpiredToken(tokenRequest.Access);
            var user = await _userManager.FindByIdAsync(principal.FindFirstValue(ClaimTypes.NameIdentifier));
            if (user == null || user.RefreshToken != tokenRequest.Refresh)
            {
                throw new SecurityTokenException("Invalid refresh token");
            }
            var datenow = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (datenow > user.ExpirationTime)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    Title = "Expiration time",
                    Detail = "Refresh token expired. Login again."
                };
            user.RefreshToken = GenerateRefreshToken(user);
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                throw new Exception("Unable to create refresh token");
            }

            return new AuthenticatedUserResponse
            {
                Access = await GenerateAccessToken(user),
                Refresh = user.RefreshToken
            };
        }
        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _authSettings.GetSecretKey(),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out _);

            return principal;
        }
    }
}
