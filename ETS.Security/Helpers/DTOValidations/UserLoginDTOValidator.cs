using ETS.Security.DTOs;
using FluentValidation;

namespace ETS.Security.Helpers.DTOValidations;

public class UserLoginDTOValidator : AbstractValidator<UserLoginDTO>
{
    public UserLoginDTOValidator()
    {
        RuleFor(u => u.Email)
            .NotEmpty()
            .WithMessage("Email is required")
            .EmailAddress();
        RuleFor(u => u.Password)
            .NotEmpty()
            .WithMessage("Password is required");
    }
}