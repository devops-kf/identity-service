using System.ComponentModel.DataAnnotations;

namespace IdentityService.Application.DTO.Requests
{
    public class UsernameSignInRequest
    {
        [Required]
        public string Username { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
