using ETS.Security.DTOs;
using ETS.Security.Models;
using ETS.Security.Services.Authentication;

namespace ETS.Security.Interfaces
{
    public interface IUserService
    {
        Task<UserDTO> GetById(string userId);
        Task<AuthenticatedUserResponse> Login(UserLoginDTO userLoginDto);
        Task<bool> Create(UserRegisterDTO userDto);
        Task<bool> IsUserExists(string email);
        Task<bool> Delete(string email);

        //email
        Task<bool> VerifyEmail(string userId, string code);
        //tokens
        Task<AuthenticatedUserResponse> VerifyAndGenerateTokens(TokenRequest tokenRequest);
        Task<AuthenticatedUserResponse> GenerateTokens(string email);
        Task<bool> SendResetCode(string email);
        Task<bool> VerifyResetCode(string email, string code, string newPassword);
    }
}
