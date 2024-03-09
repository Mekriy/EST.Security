using System.ComponentModel.DataAnnotations;
using ETS.Security.DTOs;
using ETS.Security.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using ETS.Security.Helpers;

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
                return Unauthorized("User is unauthorized");

            var user = await _userService.GetById(userId);
            if (user != null)
                return Ok(user);
            else
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Can't get user",
                    Detail = "Error occured while getting user from server"
                };
        }

        [AllowAnonymous]
        [HttpGet("{userId:Guid}")]
        public async Task<IActionResult> GetUserById([FromRoute] Guid userId)
        {
            if (userId == Guid.Empty)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    Title = "Invalid guid",
                    Detail = "Guid is empty"
                };

            var user = await _userService.GetById(userId.ToString());
            if (user != null)
                return Ok(user);
            else
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Can't get user",
                    Detail = "Error occured while getting user from server"
                };
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLoginDTO userLogin)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Failed model validation");

            var token = await _userService.Login(userLogin);
            if (token == null)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Token generation",
                    Detail = "Error occured while generating tokens for user"
                };
            return Ok(token);
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] UserRegisterDTO userRegister)
        {
            //TODO: add validation to DTOs
            if (!ModelState.IsValid)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status404NotFound,
                    Title = "Not found",
                    Detail = "User doesn't exist"
                };

            var user = await _userService.Create(userRegister);
            if (user != null)
                return Created("/api/User", user);
            else
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Token generation",
                    Detail = "Error occured while creating user on server"
                };
        }

        [AllowAnonymous]
        [HttpGet("confirm")]
        public async Task<IActionResult> EmailConfirmation([FromQuery] string userId, [FromQuery] string code)
        {
            if (userId == string.Empty || code == string.Empty)
            {
                throw new ValidationException("Invalid userId or code");
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
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Generating tokens",
                    Detail = "Error occured while generating new tokens"
                };

            return Ok(result);
        }

        [AllowAnonymous]
        [HttpPost("resetcode")]
        public async Task<IActionResult> ResettingCodeEmail([FromBody] EmailDTO emailDTO)
        {
            if (!await _userService.IsUserExists(emailDTO.To))
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status404NotFound,
                    Title = "User doesn't exist",
                    Detail = "Invalid email or user doesn't exist"
                };

            if (await _userService.SendResetCode(emailDTO.To))
            {
                return Ok("Reset code has been sent!");
            }
            else
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Sending reset code error",
                    Detail = "Error occured while sending reset code email"
                };
        }

        [AllowAnonymous]
        [HttpPost("verifyresetcode")]
        public async Task<IActionResult> VerifyingResetCode([FromBody] ResetCodeDTO resetCodeDTO)
        {
            if (!await _userService.IsUserExists(resetCodeDTO.Email))
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status404NotFound,
                    Title = "User doesn't exist",
                    Detail = "Invalid email or user doesn't exist"
                };

            if (await _userService.VerifyResetCode(resetCodeDTO.Email, resetCodeDTO.ResetToken, resetCodeDTO.NewPassword))
            {
                return Ok("Please login again");
            }
            else
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status500InternalServerError,
                    Title = "Resetting code",
                    Detail = "Error occured while resetting password on service"
                };
        }
    }
}