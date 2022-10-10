using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.DTOs.User
{
    public class ResetPasswordDTO
    {
        [Required]
        public string PasswordResetToken { get; set; } = string.Empty;
        [Required, MinLength(8, ErrorMessage = "Please enter at least 6 characters")]
        public string Password { get; set; } = string.Empty;
        [Required, Compare("Password")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
