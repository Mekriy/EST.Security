using ETS.Security.DTOs;
using ETS.Security.Models;
using ETS.Security.Services.Authentication;

namespace ETS.Security.Interfaces
{
    public interface IUserService
    {
        Task<UserDTO> GetById(string userId);
        Task<UserDTO> GetByEmail(string email);
        Task<UserDTO> Create(UserRegisterDTO userDTO);
        Task<bool> IsUserExist(string email);
        Task<bool> Delete(string email);
        Task<bool> CheckPasswords(string email, string password);

        //email
        Task<bool> VerifyEmail(string userId, string code);
        //tokens
        Task<AuthenticatedUserResponse> VerifyAndGenerateTokens(TokenRequest tokenRequest);
        Task<AuthenticatedUserResponse> GenerateTokens(string email);
        Task<bool> SendResetCode(string email);
        Task<bool> VerifyResetCode(string email, string code, string newPassword);
    }
}
