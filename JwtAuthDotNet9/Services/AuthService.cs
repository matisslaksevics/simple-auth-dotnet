using JwtAuthDotNet9.Data;
using JwtAuthDotNet9.Entities;
using JwtAuthDotNet9.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthDotNet9.Services
{
    public class AuthService(UserDbContext context, IConfiguration configuration) : IAuthService
    {
        public async Task<TokenResponseDto?> LoginAsync(UserDto request)
        {
            var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user is null)
            {
                return null;
            }
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password)
                == PasswordVerificationResult.Failed)
            {
                return null;
            }

            return await CreateTokenResponse(user);
        }

        private async Task<TokenResponseDto> CreateTokenResponse(User user)
        {
            return new TokenResponseDto
            {
                AccessToken = CreateToken(user),
                RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
            };
        }

        public async Task<User?> RegisterAsync(UserDto request)
        {
            if (await context.Users.AnyAsync(u => u.Username == request.Username))
            {
                return null;
            }

            var user = new User();
            var hashedPassword = new PasswordHasher<User>()
                .HashPassword(user, request.Password);

            user.Username = request.Username;
            user.PasswordHash = hashedPassword;
            user.Role = "User";

            context.Users.Add(user);
            await context.SaveChangesAsync();

            return user;
        }

        public async Task<TokenResponseDto?> RefreshTokensAsync(Guid userId, string refreshToken)
        {
            var user = await ValidateRefreshTokenAsync(userId, refreshToken);
            if (user is null)
                return null;

            return await CreateTokenResponse(user);
        }

        private async Task<User?> ValidateRefreshTokenAsync(Guid userId, string refreshToken)
        {
            var user = await context.Users.FindAsync(userId);
            if (user is null || user.RefreshToken != refreshToken
                || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return null;
            }

            return user;
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
        {
            var refreshToken = GenerateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await context.SaveChangesAsync();
            return refreshToken;
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
               new (ClaimTypes.NameIdentifier, user.Id.ToString()),
               new (ClaimTypes.Name, user.Username),
               new (ClaimTypes.Role, user.Role ?? "User")
            };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),
                audience: configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
        public async Task<CheckPasswordDto?> CheckPasswordAsync(Guid userId)
        {
            var user = await context.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId);
            if (user is null) return null;

            var (expiresAt, isExpired, daysRemaining) = ComputePasswordStatus(user);

            return new CheckPasswordDto
            {
                Valid = !isExpired,
                PasswordChangedAt = user.PasswordChangedAt,
                PasswordMaxAgeDays = user.PasswordMaxAgeDays,
                ExpiresAt = expiresAt,
                IsExpired = isExpired,
                DaysRemaining = daysRemaining
            };
        }

        private static (DateTime? expiresAt, bool isExpired, int? daysRemaining) ComputePasswordStatus(User user)
        {
            if (user.PasswordMaxAgeDays <= 0)
                return (null, false, null);

            var expiresAt = user.PasswordChangedAt.AddDays(user.PasswordMaxAgeDays);
            var now = DateTime.UtcNow;
            var isExpired = now >= expiresAt;
            var daysRemaining = isExpired ? 0 : (int)Math.Ceiling((expiresAt - now).TotalDays);
            return (expiresAt, isExpired, daysRemaining);
        }

        public async Task<bool> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword)
        {
            var user = await context.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user is null) return false;

            var hasher = new PasswordHasher<User>();
            var verify = hasher.VerifyHashedPassword(user, user.PasswordHash, currentPassword);
            if (verify == PasswordVerificationResult.Failed) return false;

            user.PasswordHash = hasher.HashPassword(user, newPassword);

            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;

            await context.SaveChangesAsync();
            return true;
        }

        public async Task SignOutAsync(Guid userId)
        {
            var user = await context.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user is null) return;
            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;

            await context.SaveChangesAsync();
        }
        public async Task<UserProfileDto?> GetProfileAsync(Guid userId)
        {
            var user = await context.Users.AsNoTracking()
                .FirstOrDefaultAsync(u => u.Id == userId);
            if (user is null) return null;
            return new UserProfileDto
            {
                Username = user.Username,
                Role = user.Role ?? "User"
            };
        }
        public async Task<bool> AdminSetPasswordAsync(Guid userId, string newPassword)
        {
            var user = await context.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user is null) return false;
            var hasher = new PasswordHasher<User>();
            user.PasswordHash = hasher.HashPassword(user, newPassword);
            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;
            await context.SaveChangesAsync();
            return true;
        }
        public async Task<bool> ChangeUserRoleAsync(Guid userId, string newRole)
        {
            var user = await context.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if (user is null) return false;
            user.Role = newRole;
            await context.SaveChangesAsync();
            return true;
        }
    }
}
