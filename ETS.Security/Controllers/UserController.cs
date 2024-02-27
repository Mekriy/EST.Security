using ETS.Security.DTOs;
using ETS.Security.Interfaces;
using ETS.Security.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;

namespace ETS.Security.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly UserManager<User> _userManager;
        private readonly ITokenGenerator _tokenGenerator;
        public UserController(IUserService userService, UserManager<User> userManager, ITokenGenerator tokenGenerator)
        {
            _userService = userService;
            _userManager = userManager;
            _tokenGenerator = tokenGenerator;
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLoginDTO userLogin)
        {
            var user = await _userManager.FindByEmailAsync(userLogin.Email);
            if(user == null)
                return NotFound("No user exists");

            var token = await _tokenGenerator.GenerateTokens(user);
            if (token == null)
                return StatusCode(500, "Error occured while creating token on server");
            return Ok(token);
        }
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] UserRegisterDTO userRegister)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var user = await _userManager.FindByEmailAsync(userRegister.Email);
                if (user != null)
                    return BadRequest("User is already exists!");

                if (await _userService.Create(userRegister))
                {

                    return Ok(await _tokenGenerator.GenerateTokens(await _userManager.FindByEmailAsync(userRegister.Email)));
                }
            }
            catch (Exception) { }
            
            return StatusCode(500, "Error occured while creating user on server");
        }
    }
}
