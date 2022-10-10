﻿using System.Security.Cryptography;

namespace AuthenticationAPI.Utils
{
    public static class TokenManager
    {
        public static string CreateRandomToken()
        {
            return Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
        }
    }
}
