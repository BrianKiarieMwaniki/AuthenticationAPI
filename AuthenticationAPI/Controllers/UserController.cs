using AuthenticationAPI.Data;
using AuthenticationAPI.Utils;
using AutoMapper;
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
        private readonly IMapper _mapper;
        private readonly ITokenManager _tokenManager;

        public UserController(DataContext context, IMapper mapper, ITokenManager tokenManager)
        {
            _context = context;
            _mapper = mapper;
            _tokenManager = tokenManager;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDTO request)
        {
            var user = _mapper.Map<User>(request);

            if (_context.Users.Any(u => u.Email == request.Email))
            {
                return BadRequest("User already exists.");
            }

            if (_context.Users.Any(u => u.Username == request.Username)) return BadRequest("Username already used!");

            PasswordManager.CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user = new User
            {
                Username = request.Username,
                Email = request.Email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                AccessToken = _tokenManager.CreateJwtToken(user)
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok("User successfull created!");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDTO request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email.Equals(request.Email));

            if (user is null) return BadRequest("User not found");

            if (user.VerifiedAt is null) return BadRequest("Not verified");

            if (!PasswordManager.VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
                return BadRequest("Password is incorrect...");

            if(!string.IsNullOrWhiteSpace(user.AccessToken))
            {
                if(_tokenManager.GetTokenExpireDate(user.AccessToken) < DateTime.UtcNow)
                {
                    user.AccessToken = _tokenManager.CreateJwtToken(user);
                }
            }

            await _context.SaveChangesAsync();

            return Ok(user.AccessToken);
        }


        [HttpPost("verify")]
        public async Task<IActionResult> Verify(string token)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => !string.IsNullOrWhiteSpace(u.AccessToken) && u.AccessToken.Equals(token));

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

            user.PasswordResetToken = _tokenManager.CreateJwtToken(user, isResetPasswordToken: true);
            user.ResetTokenExpires = DateTime.Now.AddHours(1);
            await _context.SaveChangesAsync();

            return Ok("You may now reset your password");
        }
        
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDTO request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => !string.IsNullOrWhiteSpace(u.PasswordResetToken) && u.PasswordResetToken.Equals(request.PasswordResetToken));


            if (user is null || user.ResetTokenExpires < DateTime.Now) return BadRequest("Invalid Token.");

            if (!string.IsNullOrWhiteSpace(user.PasswordResetToken) && _tokenManager.GetTokenExpireDate(user.PasswordResetToken) < DateTime.UtcNow)
                return BadRequest("You were too late to reset. Try Again");

            PasswordManager.CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            user.ResetTokenExpires = null;
            user.PasswordResetToken = null;

            await _context.SaveChangesAsync();

            return Ok("Password successfully reset.");
        }

    }
}
