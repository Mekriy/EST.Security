﻿namespace ETS.Security.DTOs
{
    public class ResetCodeDTO
    {
        public string ResetToken { get; set; }
        public string Email { get; set; }
        public string NewPassword { get; set; }
    }
}
