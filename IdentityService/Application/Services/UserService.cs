using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using IdentityService.Application.Domain.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IdentityService.Application.Services
{
    public class UserService : UserManager<ApplicationUser>
    {
        public UserService(
            IUserStore<ApplicationUser> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<ApplicationUser> passwordHasher,
            IEnumerable<IUserValidator<ApplicationUser>> userValidators,
            IEnumerable<IPasswordValidator<ApplicationUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<UserManager<ApplicationUser>> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
            PasswordHasher = passwordHasher;
        }

        public async Task<ApplicationUser> CreateRegularUserAsync(Guid id, string username, string password, string email, string firstName, string lastName)
        {
            return await CreateAsync(UserRole.RegularUser, id, username, password, email, firstName, lastName, UserStatus.Active);
        }

        public async Task<ApplicationUser> CreateAgentUserAsync(Guid id, string username, string password, string email, string firstName, string lastName)
        {
            return await CreateAsync(UserRole.AgentUser, id, username, password, email, firstName, lastName, UserStatus.PendingApproval);
        }

        private async Task<ApplicationUser> CreateAsync(UserRole userRole, Guid id, string username, string password, string email, string firstName, string lastName, UserStatus status)
        {
            ApplicationUser user = new()
            {
                Id = id,
                UserName = username,
                Email = email,
                FirstName = firstName,
                LastName = lastName,
                Status = status,
                EmailConfirmed = true,               // TODO (fivkovic): This should be removed after e-mail confirmation is implemented.
            };

            var createResult = await CreateAsync(user, password);
            var updateSecurityStampResult = await UpdateSecurityStampAsync(user);       // TODO (fivkovic): Why I need to do this and the other implementation not?
            var addToRoleResult = await AddToRoleAsync(user, userRole.ToString());

            return createResult.Succeeded && addToRoleResult.Succeeded && updateSecurityStampResult.Succeeded ? user : null;
        }
    }
}
