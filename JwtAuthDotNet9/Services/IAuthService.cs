using JwtAuthDotNet9.Entities;
using JwtAuthDotNet9.Models;

namespace JwtAuthDotNet9.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDto request);
        Task<TokenResponseDto?> LoginAsync(UserDto request);
        Task<TokenResponseDto?> RefreshTokensAsync(Guid userId, string refreshToken);
        Task<CheckPasswordDto?> CheckPasswordAsync(Guid userId);
        Task<bool> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword);
        Task SignOutAsync(Guid userId);
        Task<UserProfileDto?> GetProfileAsync(Guid userId);
        Task<bool> AdminSetPasswordAsync(Guid userId, string newPassword);
        Task<bool> ChangeUserRoleAsync(Guid userId, string newRole);
    }
}
