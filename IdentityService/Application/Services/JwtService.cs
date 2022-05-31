using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityService.Application.Domain.Models;
using IdentityService.Configuration;
using IdentityService.Infrastructure.Data;
using IdentityService.Infrastructure.Extensions;
using IdentityService.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using UAParser;

namespace IdentityService.Application.Services
{
    public class JwtService
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly JwtConfiguration _jwtConfiguration;
        private readonly JwtSecurityTokenHandler _tokenHandler;
        private readonly ILogger<JwtSecurityTokenHandler> _logger;
        private readonly SigningCredentials _signingCredentials;
        private readonly SecurityKey _issuerSigningKey;

        public JwtService(ApplicationDbContext dbContext,
                          JwtConfiguration jwtConfiguration,
                          AsymmetricSecurityKeyProvider securityKeyProvider,
                          ILogger<JwtSecurityTokenHandler> logger)
        {
            _dbContext = dbContext;
            _jwtConfiguration = jwtConfiguration;
            _logger = logger;
            _signingCredentials = new SigningCredentials(securityKeyProvider.PrivateKey, SecurityAlgorithms.RsaSha256);
            _issuerSigningKey = securityKeyProvider.PublicKey;
            _tokenHandler = new JwtSecurityTokenHandler();
        }

        public string GenerateAccessToken(ApplicationUser user, IEnumerable<Claim> userClaims, string loginProvider)
        {
            List<Claim> claims = new()
            {
                new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new(JwtRegisteredClaimNames.Amr, loginProvider),
                new(ClaimTypes.Email, user.Email),
            };

            if (user.FirstName is not null)
            {
                claims.Add(new(ClaimTypes.GivenName, user.FirstName));
            }

            if (user.LastName is not null)
            {
                claims.Add(new(ClaimTypes.Surname, user.LastName));
            }

            claims.AddRange(userClaims);

            SecurityTokenDescriptor tokenDescriptor = new()
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(_jwtConfiguration.AccessToken.LifetimeInMinutes),
                SigningCredentials = _signingCredentials,
                Issuer = _jwtConfiguration.Issuer,
                Audience = _jwtConfiguration.AccessToken.Purpose
            };

            SecurityToken token = _tokenHandler.CreateToken(tokenDescriptor);

            return _tokenHandler.WriteToken(token);
        }

        public async Task<RefreshToken> GenerateRefreshTokenAsync(ApplicationUser user, HttpContext httpContext, string loginProvider)
        {
            string deviceName = GetDeviceNameFromUserAgent(httpContext.Request.UserAgent());
            RefreshToken newRefreshToken = GenerateRefreshToken(user.Id);

            newRefreshToken.Name = deviceName;
            newRefreshToken.LoginProvider = loginProvider;
            // newRefreshToken.SessionId = httpContext.SessionId();
            newRefreshToken.CreatedByIp = httpContext.Request.IpAddress();

            RefreshToken tokenToRevoke = await _dbContext.UserTokens.FirstOrDefaultAsync(userToken => userToken.Value == httpContext.Request.Cookies.RefreshToken());

            if (tokenToRevoke is not null)
            {
                tokenToRevoke.Revoke(newRefreshToken.Id, newRefreshToken.CreatedByIp, DateTime.UtcNow);
            }

            _dbContext.UserTokens.Add(newRefreshToken);
            await _dbContext.SaveChangesAsync();

            return newRefreshToken;
        }

        public async Task<RefreshToken> ParseRefreshTokenAsync(string token)
        {
            JwtSecurityToken jwt = ParseJwtRefreshToken(token);

            if (jwt is null)
            {
                return null;
            }

            RefreshToken tokenInDb = await _dbContext.UserTokens.FirstOrDefaultAsync(userToken => userToken.Value == token);

            if (tokenInDb is null || !tokenInDb.IsActive)
            {
                return null;
            }

            return tokenInDb;
        }

        public async Task UpdateLastUsedAtAsync(RefreshToken token)
        {
            token.LastUsedAt = DateTime.UtcNow;
            _dbContext.UserTokens.Update(token);
            await _dbContext.SaveChangesAsync();
        }

        public async Task<bool> RevokeRefreshTokenAsync(RefreshToken tokenToRevoke, string revokingRefreshToken, string revokingIp)
        {
            var jwt = ParseJwtRefreshToken(revokingRefreshToken);

            if (jwt is null)
            {
                return false;
            }

            bool tokenIdIsValid = Guid.TryParse(jwt.Id, out Guid newTokenId);

            if (!tokenIdIsValid)
            {
                return false;
            }

            tokenToRevoke.Revoke(newTokenId, revokingIp, DateTime.UtcNow);
            _dbContext.UserTokens.Update(tokenToRevoke);

            return await _dbContext.SaveChangesAsync() != 0;
        }

        private RefreshToken GenerateRefreshToken(Guid userId)
        {
            Guid tokenId = Guid.NewGuid();

            List<Claim> claims = new()
            {
                new(JwtRegisteredClaimNames.Jti, tokenId.ToString()),
                new(JwtRegisteredClaimNames.Sub, userId.ToString()),
            };

            SecurityTokenDescriptor tokenDescriptor = new()
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(_jwtConfiguration.RefreshToken.LifetimeInDays),
                SigningCredentials = _signingCredentials,
                Issuer = _jwtConfiguration.Issuer,
                Audience = _jwtConfiguration.RefreshToken.Purpose
            };

            SecurityToken securityToken = _tokenHandler.CreateToken(tokenDescriptor);
            string refreshTokenValue = _tokenHandler.WriteToken(securityToken);

            RefreshToken refreshToken = new()
            {
                Id = tokenId,
                CreatedAt = DateTime.UtcNow,
                LastUsedAt = DateTime.UtcNow,
                ExpiresAt = tokenDescriptor.Expires.Value,
                UserId = userId,
                Value = refreshTokenValue,
            };

            return refreshToken;
        }

        private JwtSecurityToken ParseJwtRefreshToken(string token)
        {
            try
            {
                _tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    IssuerSigningKey = _issuerSigningKey,
                    ValidIssuer = _jwtConfiguration.Issuer,
                    ValidAudience = _jwtConfiguration.RefreshToken.Purpose,
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return (JwtSecurityToken)validatedToken;
            }
            catch (Exception e)
            {
                _logger.LogDebug(e.Message);
                return null;
            }
        }

        private static string GetDeviceNameFromUserAgent(string userAgent)
        {
            ClientInfo client = Parser.GetDefault().Parse(userAgent);

            bool isMissingDeviceName = client.Device.ToString() == "Other";
            string clientName = isMissingDeviceName ? client.OS.ToString() : client.Device.ToString();

            return $"{clientName}, {client.UA.Family}";
        }
    }
}
