using JwtAuthDotNet9.Entities;
using JwtAuthDotNet9.Models;

namespace JwtAuthDotNet9.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDto request);
        Task<TokenResponseDto?> LoginAsync(UserDto request);
        Task<TokenResponseDto?> RefreshTokensAsync(RefreshTokenRequestDto request);
        Task<CheckPasswordDto?> CheckPasswordAsync(Guid userId);
        Task<bool> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword);
        Task SignOutAsync(Guid userId);
    }
}
