using System;
using System.Threading.Tasks;
using IdentityService.Application.Services;
using IdentityService.Infrastructure.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace IdentityService
{
    public class Program
    {
        public async static Task Main(string[] args)
        {
            var host = CreateHostBuilder(args).Build();

            await host.MigrateDatabase();

            host.Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }

    internal static class HostExtensions
    {
        public async static Task<IHost> MigrateDatabase(this IHost host)
        {
            using (var scope = host.Services.CreateScope())
            using (var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>())
            {
                var loggerFactory = scope.ServiceProvider.GetRequiredService<ILoggerFactory>();
                var logger = loggerFactory.CreateLogger(typeof(Program));

                var userManager = scope.ServiceProvider.GetRequiredService<UserService>();
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleService>();

                try
                {
                    await dbContext.Database.MigrateAsync();

                    await ApplicationDbContextSeeder.SeedRolesAsync(roleManager, logger);
                    await ApplicationDbContextSeeder.SeedDefaultRegularUserAsync(userManager, logger);
                    await ApplicationDbContextSeeder.SeedDefaultAgentUserAsync(userManager, logger);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "An error occurred while seeding the default data in DB.");
                    throw;
                }
            }

            return host;
        }
    }
}
