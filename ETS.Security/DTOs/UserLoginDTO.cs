﻿using System.ComponentModel.DataAnnotations;

namespace ETS.Security.DTOs
{
    public class UserLoginDTO
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
