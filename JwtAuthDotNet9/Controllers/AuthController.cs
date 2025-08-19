using JwtAuthDotNet9.Entities;
using JwtAuthDotNet9.Models;
using JwtAuthDotNet9.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JwtAuthDotNet9.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            var user = await authService.RegisterAsync(request);
            if (user is null)
                return BadRequest("Username already exists.");

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(UserDto request)
        {
            var result = await authService.LoginAsync(request);
            if (result is null)
                return BadRequest("Invalid username or password.");

            return Ok(result);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto request)
        {
            var result = await authService.RefreshTokensAsync(request);
            if (result is null || result.AccessToken is null || result.RefreshToken is null)
                return Unauthorized("Invalid refresh token.");

            return Ok(result);
        }

        [Authorize]
        [HttpGet]
        public IActionResult AuthenticatedOnlyEndpoint()
        {
            return Ok("You are authenticated!");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnlyEndpoint()
        {
            return Ok("You are and admin!");
        }

        [Authorize]
        [HttpPost("check-password")]
        public async Task<IActionResult> CheckPassword([FromBody] CheckPasswordDto body)
        {
            var idStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(idStr, out var userId)) return Unauthorized();
            var ok = await authService.CheckPasswordAsync(userId, body.Password);
            return Ok(new { valid = ok });
        }

        [Authorize]
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto body)
        {
            var idStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(idStr, out var userId)) return Unauthorized();
            var changed = await authService.ChangePasswordAsync(userId, body.CurrentPassword, body.NewPassword);
            if (!changed) return BadRequest("Current password is incorrect.");

            return NoContent();
        }

        [Authorize]
        [HttpPost("signout")]
        public async Task<IActionResult> SignOut()
        {
            var idStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(idStr, out var userId)) return Unauthorized();

            await authService.SignOutAsync(userId);
            return NoContent();
        }
    }
}
