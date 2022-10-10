namespace AuthenticationAPI.Utils
{
    public interface ITokenManager
    {
        string CreateRandomToken();
        string CreateJwtToken(User user, bool isResetPasswordToken = false);
        DateTime? GetTokenExpireDate(string token);
    }
}