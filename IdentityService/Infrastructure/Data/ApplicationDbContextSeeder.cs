using System;
using System.Threading.Tasks;
using IdentityService.Application.Domain.Models;
using IdentityService.Application.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace IdentityService.Infrastructure.Data
{
    public static class ApplicationDbContextSeeder
    {
        public static async Task SeedRolesAsync(RoleManager<IdentityRole<Guid>> roleManager, ILogger logger)
        {
            foreach (UserRole userRole in Enum.GetValues(typeof(UserRole)))
            {
                var identityRole = new IdentityRole<Guid>(userRole.ToString());

                var persistedIdentityRole = await roleManager.FindByNameAsync(identityRole.Name);
                if (persistedIdentityRole is null)
                {
                    await roleManager.CreateAsync(identityRole);
                    logger.LogInformation($"Added '{identityRole.Name}' to Roles");
                }
            }
        }

        public static async Task SeedDefaultRegularUserAsync(UserService userService, ILogger logger)
        {
            var user = await userService.FindByEmailAsync("regular.user@nistagram.com");
            if (user is null)
            {
                await userService.CreateRegularUserAsync(
                    id: Guid.Parse("41B3A327-531E-48FE-8D77-B22B035DC53A"),
                    username: "regular",
                    password: "regular",
                    email: "regular.user@nistagram.com",
                    firstName: "Regular",
                    lastName: "User");

                logger.LogInformation($"Added default REGULAR user.");
            }
        }

        public static async Task SeedDefaultAgentUserAsync(UserService userService, ILogger logger)
        {
            var user = await userService.FindByEmailAsync("agent.user@nistagram.com");
            if (user is null)
            {
                await userService.CreateAgentUserAsync(
                    id: Guid.Parse("382F6D65-F620-48A4-AE6D-2EF8CC46FC71"),
                    username: "agent",
                    password: "agent",
                    email: "agent.user@nistagram.com",
                    firstName: "Agent",
                    lastName: "User");

                logger.LogInformation($"Added default AGENT user.");
            }
        }
    }
}
