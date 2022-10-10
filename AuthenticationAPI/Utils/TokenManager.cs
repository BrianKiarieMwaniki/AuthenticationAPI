using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticationAPI.Utils
{
    public class TokenManager : ITokenManager
    {
        private readonly IConfiguration _configuration;
        private readonly JwtSecurityTokenHandler _tokenHandler;
        private byte[] secretKey;

        public TokenManager(IConfiguration configuration)
        {
            _configuration = configuration;
            _tokenHandler = new JwtSecurityTokenHandler();
            secretKey = Encoding.ASCII.GetBytes(_configuration.GetValue<string>("secretkey"));
        }

        public string CreateRandomToken()
        {
            return Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
        }

        public string CreateJwtToken(User user, bool isResetPasswordToken = false)
        {
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Name, user.Username));
            claims.Add(new Claim(ClaimTypes.Email, user.Email));


            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = isResetPasswordToken ? DateTime.UtcNow.AddMinutes(5): DateTime.UtcNow.AddHours(2),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(secretKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = _tokenHandler.CreateToken(tokenDescriptor);

            return _tokenHandler.WriteToken(token);
        }

        

        public DateTime? GetTokenExpireDate(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return null;

            var jwtToken = _tokenHandler.ReadToken(token.Replace("\"", string.Empty)) as JwtSecurityToken;

            var expireDate = jwtToken?.ValidTo;

            return expireDate;
        }
    }
}
