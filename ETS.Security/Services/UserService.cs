using ETS.Security.DataAccess;
using ETS.Security.DTOs;
using ETS.Security.Helpers;
using ETS.Security.Interfaces;
using ETS.Security.Models;
using Microsoft.AspNetCore.Identity;
using MimeKit;
using MimeKit.Text;
using MailKit.Net.Smtp;
using MailKit.Security;
using ETS.Security.Services.Authentication;
using Microsoft.EntityFrameworkCore;
using Exception = System.Exception;

namespace ETS.Security.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<User> _userManager;
        private readonly ITokenGenerator _tokenGenerator;
        private readonly SecurityContext _context;

        public UserService(
            UserManager<User> userManager,
            ITokenGenerator tokenGenerator,
            SecurityContext context)
        {
            _userManager = userManager;
            _tokenGenerator = tokenGenerator;
            _context = context;
        }
        public async Task<UserDTO> GetById(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            var userRole = await _userManager.GetRolesAsync(user);
            var userDTO = new UserDTO
            {
                UserName = user.UserName,
                Email = user.Email,
                RoleName = userRole.FirstOrDefault() ?? string.Empty
            };
            return userDTO;
        }

        public async Task<AuthenticatedUserResponse> Login(UserLoginDTO userLoginDto)
        {
            var isExist = await IsUserExists(userLoginDto.Email);
            if (!isExist)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status404NotFound,
                    Title = "User doesn't exist",
                    Detail = "User doesn't exist while creating user"
                };
            
            var isEmailVerified = await IsEmailVerified(userLoginDto.Email);
            if (!isEmailVerified)
            {
                var user = await _userManager.FindByEmailAsync(userLoginDto.Email);
                //TODO: this will send mails everytime user is doing the login. In a real project you would be probably checking to be sure that you do not send emails more than once per day etc.
                await SendEmail(user); 
                throw new ApiException
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    Title = "Email is not confirmed",
                    Detail = "User email is not confirmed. Email was sent again"
                };
            }
            var doesPasswordMatch = await CheckPasswords(userLoginDto);
            if(!doesPasswordMatch)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    Title = "Wrong password",
                    Detail = "Password doesn't match"
                };
            var tokens = await GenerateTokens(userLoginDto.Email);
            
            return tokens;
        }

        private async Task<bool> IsEmailVerified(string email)
        {
            return (await _userManager.FindByEmailAsync(email)).EmailConfirmed;
        }
        public async Task<bool> Create(UserRegisterDTO userDTO)
        {
            var isExist = await IsUserExists(userDTO.Email);
            if (isExist)
                throw new ApiException()
                {
                    StatusCode = StatusCodes.Status400BadRequest,
                    Title = "Invalid email",
                    Detail = "Email is already used! Try different one"
                };

            var createUserResult = await CreateUser(userDTO);
            if (createUserResult)
            {
                var createdUser = await _userManager.FindByEmailAsync(userDTO.Email);
                await AddRoleToUser(createdUser);
                var isEmailSent = await SendEmail(createdUser);
                if (isEmailSent)
                {
                    return isEmailSent;
                }
                else
                {
                    await _userManager.DeleteAsync(createdUser);
                    throw new ApiException()
                    {
                        StatusCode = StatusCodes.Status500InternalServerError,
                        Title = "Can't send email",
                        Detail = "Error occured while sending email. Deleting user"
                    };
                }
            }

            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Can't creating user",
                Detail = "Error occured while creating user on server"
            };
        }
    
        private async Task<bool> CreateUser(UserRegisterDTO userDto)
        {
            var user = new User()
            {
                UserName = userDto.UserName,
                Email = userDto.Email,
            };
            var createResult = await _userManager.CreateAsync(user, userDto.Password);
            return createResult.Succeeded;
        }

        private async Task<string> AddRoleToUser(User user)
        {
            var result = await _userManager.AddToRoleAsync(user, "User");
            if (result.Succeeded)
            {
                var role = await _userManager.GetRolesAsync(user);
                return role.First();
            }

            throw new ApiException()
            {
                StatusCode = StatusCodes.Status500InternalServerError,
                Title = "Can't add role to user",
                Detail = "Error occured while adding role to user"
            };
        }

        public async Task<bool> Delete(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            var result = await _userManager.DeleteAsync(user);
            return result.Succeeded;
        }

        public async Task<bool> IsUserExists(string email)
        {
            return await _context.Users.Where(u => u.Email.ToLower() == email.ToLower()).AnyAsync();
        }

        private async Task<bool> CheckPasswords(UserLoginDTO userLoginDto)
        {
            var user = await _userManager.FindByEmailAsync(userLoginDto.Email);
            return await _userManager.CheckPasswordAsync(user, userLoginDto.Password);
        }

        private async Task<bool> SendEmail(User user)
        {
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = CallbackUrl(user.Id, code);

            try
            {
                var email = new MimeMessage();
                email.From.Add(MailboxAddress.Parse("todo.dar.ltd@gmail.com"));
                email.To.Add(MailboxAddress.Parse(user.Email));
                email.Subject = "Email Verification";
                email.Body = new TextPart(TextFormat.Html)
                {
                    Text = $@"<!DOCTYPE html>
<html>
<head>
  <meta http-equiv=""Content-Type"" content=""text/html"" charset=""UTF-8"" />
  <title>Email Verification</title>
  <link rel=""preconnect"" href=""https://fonts.googleapis.com"">
  <link rel=""preconnect"" href=""https://fonts.gstatic.com"" crossorigin>
  <link href=""https://fonts.googleapis.com/css2?family=Roboto:ital,wght@0,100;0,300;0,400;0,500;0,700;0,900;1,100;1,300;1,400;1,500;1,700;1,900&display=swap"" rel=""stylesheet"">   
  <style>
    .button-container{{
        margin: 10px;
    }}
    .verify-button {{
      background: transparent;
      color: black;
      width: 110px;
      height: 35px;
      font-family: 'Roboto';
      font-size: 1em;
      border: 2px solid black;
      border-radius: 20px;
      text-decoration: none;
      display: inline-block;
      line-height: 35px;
      text-align: center;
    }}
    a{{
      text-decoration: none;
    }}
    a.link{{
      color:white;
    }}
    a.visited{{
      color:pink;
    }}
    a.active{{
      color:white;
    }}
    .email-text {{
      color: #333;
      font-size: 1em;
      font-size: 1em;
      margin-top: 5px;
      margin: 0px;
    }}
    .table-text{{
        font-family: 'Roboto';
        background-color: lightblue;
        border-radius: 15px;
        padding: 10px;
    }}
  </style>
</head>
<body>

  <table class=""table-text"">
    <tr>
      <td>
        <h2>Email Verification</h2>
        <p class=""email-text"">Thank you for signing up! To verify your email address, please click the link below:</p>
      </td>
    </tr>
    <tr>
      <td style=""text-align: center;"">
        <div class=""button-container"">
          <a class=""verify-button"" href=""{callbackUrl}"">Verify Email</a>
        </div>
      </td>
    </tr>
    <tr>
      <td>
        <p class=""email-text"">If button doesn't work follow this link: </p>
        <p class=""email-text"">{callbackUrl}</p>
        <p class=""email-text"" style=""margin-top: 20px;"">If you didn't sign up for this service, please ignore this email.</p>
        <p class=""email-text"">Best regards,</p>
        <p class=""email-text"">Spendify</p>
      </td>
    </tr>
  </table>
</body>
</html>"
                };

                using var smtp = new SmtpClient();
                await smtp.ConnectAsync("smtp.gmail.com", 587, SecureSocketOptions.StartTls);
                await smtp.AuthenticateAsync("todo.dar.ltd@gmail.com", "jtql lwsx jtja vkej");

                await smtp.SendAsync(email);
                await smtp.DisconnectAsync(true);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private string CallbackUrl(Guid userId, string code)
        {
            var ngrok = ConstantVariables.ngrok;
            var callbackUrl = ngrok + "/api/User/confirm" + $"?userId={userId.ToString()}&code={code}";
            return callbackUrl;
        }

        public async Task<bool> VerifyEmail(string userId, string code)
        {
            code = code.Replace(' ', '+');
            var user = await _userManager.FindByIdAsync(userId);
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return result.Succeeded;
        }

        public async Task<AuthenticatedUserResponse> VerifyAndGenerateTokens(TokenRequest tokenRequest)
        {
            return await _tokenGenerator.RefreshAccessToken(tokenRequest);
        }

        public async Task<AuthenticatedUserResponse> GenerateTokens(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            return await _tokenGenerator.GenerateTokens(user);
        }

        public async Task<bool> SendResetCode(string emailDto)
        {
            var user = await _userManager.FindByEmailAsync(emailDto);
            var resetCode = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callbackUrl = "http://localhost:4200/" + "verified-password-reset" + $"?userEmail={user.Email}&code={resetCode}";
            try
            {
                var email = new MimeMessage();
                email.From.Add(MailboxAddress.Parse("todo.dar.ltd@gmail.com"));
                email.To.Add(MailboxAddress.Parse(user.Email));
                email.Subject = "Reset password";
                email.Body = new TextPart(TextFormat.Html)
                {
                    Text = $@"<!DOCTYPE html>
<html>
<head>
  <meta http-equiv=""Content-Type"" content=""text/html""; charset=""UTF-8""/>
  <title>Reset password</title>
  <style type=""text/css"">
      .resetCode{{
      padding: 10px;
      display: inline;
      border: 5px solid #999;
      font-size: 40px;
    }}
</style>
</head>
<body>

  <table cellpadding=""0"" cellspacing=""0"" border=""0"">
    <tr>
      <td>
        <h2>Password Reset</h2>
        <p>We have received a request to reset your password. Please follow the link to the page</p>
        <p>On this page you can type your new password:</p>
      </td>
    </tr>
    <tr>
        <td style=""text-align: center;"">
        <div class=""button-container"">
          <a class=""verify-button"" href=""{callbackUrl}"">Reset password</a>
        </div>
        </td>
    </tr>
    <tr>  
        <td>
        <p>If you did not initiate this password reset, we recommend changing your password immediately to secure your account.</p>
        <p style=""margin-bottom: 5px;"">Best regards,</p>
        <p style= ""margin: 0px;"">Spendify</p>
      </td>
    </tr>
  </table>
</body>
</html>"
                };

                using var smtp = new SmtpClient();
                await smtp.ConnectAsync("smtp.gmail.com", 587, SecureSocketOptions.StartTls);
                await smtp.AuthenticateAsync("todo.dar.ltd@gmail.com", "jtql lwsx jtja vkej");

                await smtp.SendAsync(email);
                await smtp.DisconnectAsync(true);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public async Task<bool> VerifyResetCode(string email, string code, string newPassword)
        {
            code = code.Replace(' ', '+');
            var user = await _userManager.FindByEmailAsync(email);
            var result = await _userManager.ResetPasswordAsync(user, code, newPassword);
            if (result.Succeeded)
                return true;
            else
                throw new Exception();
        }
    }
}