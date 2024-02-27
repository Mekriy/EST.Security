using ETS.Security.DataAccess;
using ETS.Security.DTOs;
using ETS.Security.Interfaces;
using ETS.Security.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace ETS.Security.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole<Guid>> _roleManager;

        public UserService(UserManager<User> userManager, RoleManager<IdentityRole<Guid>> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<bool> Create(UserRegisterDTO userDTO)
        {
            var user = new User()
            {
                UserName = userDTO.UserName,
                Email = userDTO.Email,
            };
            var createResult = await _userManager.CreateAsync(user, userDTO.Password);
            if (createResult.Succeeded)
            {
                
                var createdUser = await _userManager.FindByEmailAsync(user.Email);
                var addRoleResult = await _userManager.AddToRoleAsync(createdUser, "User");
                return addRoleResult.Succeeded;
            }
            else
                return false;
        }
    }
}
