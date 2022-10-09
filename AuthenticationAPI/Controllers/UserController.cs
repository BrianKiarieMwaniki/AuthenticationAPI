using AuthenticationAPI.Data;
using AuthenticationAPI.Utils;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticationAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly DataContext _context;

        public UserController(DataContext context)
        {
            _context = context;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserRegistrationRequest request)
        {
            if (_context.Users.Any(u => u.Email == request.Email))
            {
                return BadRequest("User already exists.");
            }

            PasswordHelper.CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            var user = new User
            {
                Email = request.Email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                VerificationToken = TokenHelper.CreateRandomToken()
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok("User successfull created!");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserLoginRequest request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email.Equals(request.Email));

            if (user is null) return BadRequest("User not found");

            if (user.VerifiedAt is null) return BadRequest("Not verified");

            if (!PasswordHelper.VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
                return BadRequest("Password is incorrect...");

            return Ok($"Welcome back, {user.Email}!😊");
        }


        [HttpPost("verify")]
        public async Task<IActionResult> Verify(string token)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => !string.IsNullOrWhiteSpace(u.VerificationToken) && u.VerificationToken.Equals(token));

            if (user is null) return BadRequest("Invalid token");

            user.VerifiedAt = DateTime.Now;
            await _context.SaveChangesAsync();

            return Ok("User verified!😉");
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email.Equals(email));

            if (user is null) return BadRequest("User not found.");

            user.PasswordResetToken = TokenHelper.CreateRandomToken();
            user.ResetTokenExpires = DateTime.Now.AddHours(1);
            await _context.SaveChangesAsync();

            return Ok("You may now reset your password");
        }
        
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordRequest request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => !string.IsNullOrWhiteSpace(u.PasswordResetToken) && u.PasswordResetToken.Equals(request.Token));

            if (user is null || user.ResetTokenExpires < DateTime.Now) return BadRequest("Invalid Token.");

            PasswordHelper.CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            user.ResetTokenExpires = null;
            user.PasswordResetToken = null;

            await _context.SaveChangesAsync();

            return Ok("Password successfully reset.");
        }

    }
}
