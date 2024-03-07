using ETS.Security.DTOs;
using ETS.Security.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace ETS.Security.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> GetUser()
        {
            var userId = HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
                return Unauthorized("User is not authorized");

            var user = await _userService.GetById(userId);
            if (user == null)
                return NotFound("No user found");
            else
                return Ok(user);
        }

        [AllowAnonymous]
        [HttpGet("{userId:Guid}")]
        public async Task<IActionResult> GetUserById([FromRoute] Guid userId)
        {
            if (userId == Guid.Empty)
                return BadRequest("No guid");

            var user = await _userService.GetById(userId.ToString());
            if (user == null)
                return NotFound("No user found");
            else
                return Ok(user);
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLoginDTO userLogin)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            if (!await _userService.IsUserExist(userLogin.Email))
                return NotFound("No user exists");

            if (!await _userService.CheckPasswords(userLogin.Email, userLogin.Password))
                return BadRequest("Password doesn't match");

            var token = await _userService.GenerateTokens(userLogin.Email);
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
                //TODO: add validation to DTOs
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var user = await _userService.Create(userRegister);
                if (user != null)
                    return Created("/api/User", user);
                else
                    return StatusCode(500, "Error occured while creating user on server");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        [AllowAnonymous]
        [HttpGet("confirm")]
        public async Task<IActionResult> EmailConfirmation([FromQuery] string userId, [FromQuery] string code)
        {
            if (userId == string.Empty || code == string.Empty)
            {
                return BadRequest("No user id or code");
            }

            if (await _userService.VerifyEmail(userId, code))
                return Content(ConstantVariables.htmlSuccessVerification, "text/html");
            else
                return Content(ConstantVariables.htmlFailVerification, "text/html");
        }

        [HttpPost("tokens")]
        public async Task<IActionResult> RefreshingTokens([FromBody] TokenRequest tokenRequest)
        {
            var result = await _userService.VerifyAndGenerateTokens(tokenRequest);
            if (result.AccessToken == null || result.RefreshToken == null)
                return StatusCode(500, "Error occured while generating new tokens");

            return Ok(result);
        }

        [AllowAnonymous]
        [HttpPost("resetcode")]
        public async Task<IActionResult> ResettingCodeEmail([FromBody] EmailDTO emailDTO)
        {
            if (!await _userService.IsUserExist(emailDTO.To))
                return BadRequest("Invalid email or user doesn't exist");

            if (await _userService.SendResetCode(emailDTO.To))
            {
                return Ok("Reset code has been sent!");
            }
            else
                return StatusCode(500, "Error occured while sending reset code email");
        }

        [AllowAnonymous]
        [HttpPost("verifyresetcode")]
        public async Task<IActionResult> VerifyingResetCode([FromBody] ResetCodeDTO resetCodeDTO)
        {
            if (!await _userService.IsUserExist(resetCodeDTO.Email))
                return BadRequest("Invalid email or user doesn't exist");

            if (await _userService.VerifyResetCode(resetCodeDTO.Email, resetCodeDTO.ResetToken, resetCodeDTO.NewPassword))
            {
                return Ok("Please login again");
            }
            else
                return StatusCode(500, "Error occured while resetting password on service");
        }
    }
}

//TODO: Create global exception handling