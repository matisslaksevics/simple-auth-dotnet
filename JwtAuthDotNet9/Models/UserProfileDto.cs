using System;

namespace JwtAuthDotNet9.Models
{
    public class UserProfileDto
    {
        public required string Username { get; set; }
        public required string Role { get; set; }
    }
}
