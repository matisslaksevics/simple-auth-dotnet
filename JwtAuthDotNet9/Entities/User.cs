namespace JwtAuthDotNet9.Entities
{
    public class User
    {
        public Guid Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
        public DateTime PasswordChangedAt { get; set; } = DateTime.UtcNow;
        public int PasswordMaxAgeDays { get; set; } = 90;
    }
}
