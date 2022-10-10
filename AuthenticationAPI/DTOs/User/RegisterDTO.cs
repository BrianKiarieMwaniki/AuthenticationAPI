﻿using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.DTOs.User
{
    public class RegisterDTO
    {
        [Required]
        public string Username { get; set; } = string.Empty;
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        [Required, MinLength(8, ErrorMessage = "Please enter at least 8 characters")]
        public string Password { get; set; } = string.Empty;
        [Required, Compare("Password")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
