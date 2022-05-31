using System;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Application.Domain.Models
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public UserStatus Status { get; set; }
        public bool HasPassword => !string.IsNullOrWhiteSpace(PasswordHash);
    }
}
