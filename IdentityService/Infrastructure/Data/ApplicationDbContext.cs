using System;
using System.IO;
using IdentityService.Application.Domain.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace IdentityService.Infrastructure.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser,
                                                          IdentityRole<Guid>,
                                                          Guid,
                                                          IdentityUserClaim<Guid>,
                                                          IdentityUserRole<Guid>,
                                                          IdentityUserLogin<Guid>,
                                                          IdentityRoleClaim<Guid>,
                                                          RefreshToken>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<ApplicationUser>().ToTable("Users");
            builder.Entity<IdentityRole<Guid>>().ToTable("Roles");
            builder.Entity<IdentityUserClaim<Guid>>().ToTable("UserClaims");
            builder.Entity<IdentityUserRole<Guid>>().ToTable("UserRoles")
                .HasKey(k => new { k.UserId, k.RoleId });
            builder.Entity<IdentityUserLogin<Guid>>().ToTable("UserLogins")
                .HasKey(k => new { k.LoginProvider, k.ProviderKey });
            builder.Entity<IdentityRoleClaim<Guid>>().ToTable("RoleClaims");
            builder.Entity<RefreshToken>().ToTable("RefreshTokens")
                .HasKey(k => k.Id);
        }
    }

    public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .Build();

            var builder = new DbContextOptionsBuilder<ApplicationDbContext>();
            var connectionString = configuration.GetConnectionString("MigrationContextConnection");

            builder.UseSqlServer(connectionString);

            return new(builder.Options);
        }
    }
}
