namespace JwtAuthDotNet9.Models
{
    public class AdminPasswordChangeDto
    {
        public Guid Id { get; set; }
        public required string NewPassword { get; set; }
    }
}
