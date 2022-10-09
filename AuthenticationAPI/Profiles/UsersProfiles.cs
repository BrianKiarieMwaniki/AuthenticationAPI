using AutoMapper;

namespace AuthenticationAPI.Profiles
{
    public class UsersProfiles : Profile
    {
        public UsersProfiles()
        {
            CreateMap<RegisterDTO, User>();
            CreateMap<LoginDTO, User>();
            CreateMap<ResetPasswordDTO, User>();
        }
    }
}
