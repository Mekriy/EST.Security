using ETS.Security.DTOs;

namespace ETS.Security.Interfaces
{
    public interface IUserService
    {
        Task<bool> Create(UserRegisterDTO userDTO);
    }
}
