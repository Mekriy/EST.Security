using ETS.Security.DTOs;
using FluentValidation;

namespace ETS.Security.Helpers.DTOValidations;

public class ResetCodeDTOValidator : AbstractValidator<ResetCodeDTO>
{
    public ResetCodeDTOValidator()
    {
        RuleFor(u => u.Email)
            .NotEmpty()
            .WithMessage("Email is required")
            .EmailAddress();
        RuleFor(u => u.ResetToken)
            .NotEmpty()
            .WithMessage("Reset code is required");
    }
}