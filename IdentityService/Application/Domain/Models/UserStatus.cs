namespace IdentityService.Application.Domain.Models
{
    public enum UserStatus
    {
        Created = 0,
        PendingApproval,
        Active,
        Suspended
    }
}
