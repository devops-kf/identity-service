using System;
using IdentityService.Application.Domain.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Application.Services
{
    /// <summary>
    /// ASP.NET Core Identity password hasher using the bcrypt password hashing algorithm.
    /// </summary>
    public class BCryptPasswordHasher : IPasswordHasher<ApplicationUser>
    {
        /// <summary>
        /// Hashes a password using bcrypt password hashing algorithm.
        /// </summary>
        /// <param name="user">Not used for this implementation</param>
        /// <param name="password">plaintext password</param>
        /// <returns>hashed password</returns>
        /// <exception cref="ArgumentNullException">missing plaintext password</exception>
        public string HashPassword(ApplicationUser user, string password)
        {
            if (user is null) throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));

            return BCrypt.Net.BCrypt.HashPassword(inputKey: password, workFactor: 12, enhancedEntropy: false);
        }

        /// <summary>
        /// Verifies a plaintext password against a stored hash.
        /// </summary>
        /// <param name="user">Not used for this implementation</param>
        /// <param name="hashedPassword">The stored, hashed password</param>
        /// <param name="providedPassword">The plaintext password to verify against the stored hash</param>
        /// <returns>
        /// Returns Success if the password matches the stored password. 
        /// Returns SuccessRehashNeeded if the work factor has changed.
        /// Returns Failed if the validation failed.
        /// </returns>
        /// <exception cref="ArgumentNullException">In case of missing plaintext password or hashed password</exception>
        public PasswordVerificationResult VerifyHashedPassword(ApplicationUser user, string hashedPassword, string providedPassword)
        {
            if (user is null) throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(hashedPassword)) throw new ArgumentNullException(nameof(hashedPassword));
            if (string.IsNullOrWhiteSpace(providedPassword)) throw new ArgumentNullException(nameof(providedPassword));

            var isValid = BCrypt.Net.BCrypt.Verify(providedPassword, hashedPassword, enhancedEntropy: false);
            if (isValid && BCrypt.Net.BCrypt.PasswordNeedsRehash(hashedPassword, newMinimumWorkLoad: 12))
            {
                return PasswordVerificationResult.SuccessRehashNeeded;
            }

            return isValid ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
    }
}
