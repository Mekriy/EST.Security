using ETS.Security.DTOs;
using FluentValidation;

namespace ETS.Security.Helpers.DTOValidations;

public class UserRegisterDTOValidator : AbstractValidator<UserRegisterDTO>
{
    public UserRegisterDTOValidator()
    {
        RuleFor(u => u.Email)
            .NotEmpty()
            .WithMessage("Email is required")
            .EmailAddress();
        RuleFor(u => u.UserName)
            .NotEmpty()
            .WithMessage("UserName is required");
        RuleFor(u => u.UserName)
            .Must(u => u.Length > 1)
            .WithMessage("At least 2 characters in name");
        RuleFor(u => u.Password)
            .NotEmpty()
            .WithMessage("Password is required");
    }
}