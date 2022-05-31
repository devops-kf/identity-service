using System;

namespace AuthenticationAPI.Application.DTO
{
    public class UserDto
    {
        public Guid Id { get; private set; }
        public string UserName { get; private set; }
        public string Email { get; private set; }
        public string FirstName { get; private set; }
        public string LastName { get; private set; }
    }
}
