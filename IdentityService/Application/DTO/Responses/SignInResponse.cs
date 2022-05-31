using AuthenticationAPI.Application.DTO;

namespace IdentityService.Application.DTO.Responses
{
    public class SignInResponse
    {
        public string AccessToken { get; set; }

        public UserDto User { get; set; }
    }
}
