namespace JwtAuthDotNet9.Models
{
    public class ChangeUserRoleDto
    {
        public required Guid Id { get; set; }
        public required string NewRole { get; set; }
    }
}
