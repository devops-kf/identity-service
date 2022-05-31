using System;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Application.Domain.Models
{
    public class RefreshToken : IdentityUserToken<Guid>
    {
        public Guid Id { get; set; }
        public Guid SessionId { get; set; }
        public DateTime ExpiresAt { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? RevokedAt { get; set; }
        public DateTime LastUsedAt { get; set; }
        public string CreatedByIp { get; set; }
        public string RevokedByIp { get; set; }
        public Guid ReplacedByToken { get; set; }
        public bool HasExpired => DateTime.UtcNow >= ExpiresAt;
        public bool IsActive => RevokedAt == null && !HasExpired;

        public void Revoke(Guid revokedById, string revokedByIp, DateTime revokedAt)
        {
            RevokedAt = revokedAt;
            RevokedByIp = revokedByIp;
            ReplacedByToken = revokedById;
        }

        public override string ToString()
        {
            return Value;
        }
    }
}
