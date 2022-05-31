using System.ComponentModel.DataAnnotations;

namespace IdentityService.Application.DTO.Requests
{
    public class EmailSignInRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
