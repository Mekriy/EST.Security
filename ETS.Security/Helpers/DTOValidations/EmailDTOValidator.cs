using ETS.Security.DTOs;
using FluentValidation;

namespace ETS.Security.Helpers.DTOValidations;

public class EmailDTOValidator : AbstractValidator<EmailDTO>
{
    public EmailDTOValidator()
    {
        RuleFor(u => u.To)
            .NotEmpty()
            .WithMessage("Email is required")
            .EmailAddress();
    }
}