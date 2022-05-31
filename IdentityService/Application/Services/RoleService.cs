using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace IdentityService.Application.Services
{
    public class RoleService : RoleManager<IdentityRole<Guid>>
    {
        public RoleService(
            IRoleStore<IdentityRole<Guid>> store,
            IEnumerable<IRoleValidator<IdentityRole<Guid>>> roleValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            ILogger<RoleManager<IdentityRole<Guid>>> logger)
            : base(store, roleValidators, keyNormalizer, errors, logger)
        {
        }
    }
}
