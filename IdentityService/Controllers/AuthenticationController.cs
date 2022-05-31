using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using AuthenticationAPI.Application.DTO;
using IdentityService.Application.Domain.Models;
using IdentityService.Application.DTO.Requests;
using IdentityService.Application.DTO.Responses;
using IdentityService.Application.Services;
using IdentityService.Configuration;
using IdentityService.Infrastructure.Extensions;
using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace IdentityService.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("v{version:apiVersion}/")]
    public class AuthenticationController : ControllerBase
    {
        // TODO (fivkovic): Use part of the code from EmailSignUp to handle events from RabbitMQ

        private readonly UserService _userService;
        private readonly JwtService _jwtService;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<AuthenticationController> _logger;

        private readonly string _loginProvider = "api.nistagram.com";

        public AuthenticationController(UserService userService, JwtService jwtService, SignInManager<ApplicationUser> signInManager, ILogger<AuthenticationController> logger)
        {
            _userService = userService;
            _jwtService = jwtService;
            _signInManager = signInManager;
            _logger = logger;
        }

        [AllowAnonymous]
        [Authorize]
        [HttpGet("[Action]")]
        public ActionResult Test()
        {
            _logger.LogInformation($"Test endpoint hit from {Request.Host}.");

            HttpContext.Response.Headers.Add("X-Test-Header", "Working");

            return User.Identity.IsAuthenticated ? Ok($"Authenticated user with ID { User.Id() }") : Ok("Anonymous user");
        }

        /// <summary>
        /// Signs a user in using an username and password.
        /// </summary>
        /// <remarks>
        /// Password validation rules are not enforced on sign in.
        /// </remarks>
        /// <response code="200">Returns a success message.</response>
        /// <response code="400">Returns a response with an "errors" dictionary that has an "username", "email" or "password" key which contains an array of errors.</response>
        /// <response code="400">If all else fails returns a response with a detail field indicating the error.</response>
        [HttpPost("username-login")]
        [ProducesResponseType(typeof(SignInResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<SignInResponse>> UsernameSignIn(UsernameSignInRequest request)
        {
            ApplicationUser user = await _userService.FindByNameAsync(request.Username);
            if (user is null)
            {
                ModelState.AddModelError("username", $"User with username {request.Username} does not exist");
                return ValidationProblem(ModelState);
            }

            if (!user.EmailConfirmed)
            {
                ModelState.AddModelError("email", "Email not confirmed");
                return ValidationProblem(ModelState);
            }

            var signInResult = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: false);
            if (!signInResult.Succeeded)
            {
                string passwordInvalid = "Invalid password";
                string message = signInResult switch
                {
                    { IsLockedOut: true } => "User locked out.",
                    { IsNotAllowed: true } => "Sign in not allowed.",
                    { RequiresTwoFactor: true } => "Two factor authentication required.",
                    _ => passwordInvalid,
                };

                if (message == passwordInvalid)
                {
                    ModelState.AddModelError("password", passwordInvalid);
                    return ValidationProblem(ModelState);
                }
                return Problem(message);
            }

            var userClaims = await _userService.GetClaimsAsync(user);

            var refreshTokenTask = _jwtService.GenerateRefreshTokenAsync(user, HttpContext, _loginProvider);
            string accessToken = _jwtService.GenerateAccessToken(user, userClaims, _loginProvider);

            RefreshToken refreshToken = await refreshTokenTask;
            Response.Cookies.AppendRefreshToken(refreshToken.Value);

            return Ok(new SignInResponse { AccessToken = accessToken, User = user.Adapt<UserDto>() });
        }

        /// <summary>
        /// Signs a user in using an email and password.
        /// </summary>
        /// <remarks>
        /// Password validation rules are not enforced on sign in.
        /// </remarks>
        /// <response code="200">Returns a success message.</response>
        /// <response code="400">Returns a response with an "errors" dictionary that has an "email" or "password" key which contains an array of errors.</response>
        /// <response code="400">If all else fails returns a response with a detail field indicating the error.</response>
        [HttpPost("email-login")]
        [ProducesResponseType(typeof(SignInResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<SignInResponse>> EmailSignIn(EmailSignInRequest request)
        {
            ApplicationUser user = await _userService.FindByEmailAsync(request.Email);
            if (user is null)
            {
                ModelState.AddModelError("email", $"User with email {request.Email} does not exist");
                return ValidationProblem(ModelState);
            }

            if (!user.EmailConfirmed)
            {
                ModelState.AddModelError("email", "Email not confirmed");
                return ValidationProblem(ModelState);
            }

            var signInResult = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: false);
            if (!signInResult.Succeeded)
            {
                string passwordInvalid = "Invalid password";
                string message = signInResult switch
                {
                    { IsLockedOut: true } => "User locked out.",
                    { IsNotAllowed: true } => "Sign in not allowed.",
                    { RequiresTwoFactor: true } => "Two factor authentication required.",
                    _ => passwordInvalid,
                };

                if (message == passwordInvalid)
                {
                    ModelState.AddModelError("password", passwordInvalid);
                    return ValidationProblem(ModelState);
                }
                return Problem(message);
            }

            var userClaims = await _userService.GetClaimsAsync(user);

            var refreshTokenTask = _jwtService.GenerateRefreshTokenAsync(user, HttpContext, _loginProvider);
            string accessToken = _jwtService.GenerateAccessToken(user, userClaims, _loginProvider);

            RefreshToken refreshToken = await refreshTokenTask;
            Response.Cookies.AppendRefreshToken(refreshToken.Value);

            return Ok(new SignInResponse { AccessToken = accessToken, User = user.Adapt<UserDto>() });
        }

        /// <summary>
        /// Exchange a JWT Refresh Token for a JWT Access Token.
        /// </summary>
        /// <remarks>
        /// Method succeeds only if a correct refresh_token Cookie is supplied.
        /// </remarks>
        /// <response code="200">Returns a success message.</response>
        /// <response code="400">Returns an error message.</response>
        [HttpGet("token/refresh")]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(string), StatusCodes.Status400BadRequest)]
        public async Task<ActionResult> TokenRefresh()
        {
            string token = Request.Cookies.RefreshToken();

            if (token is null)
            {
                return BadRequest($"No {RefreshTokenConfiguration.CookieName} cookie found.");
            }

            RefreshToken refreshToken = await _jwtService.ParseRefreshTokenAsync(token);

            if (refreshToken is null)
            {
                return BadRequest("Refresh token invalid.");
            }

            ApplicationUser user = await _userService.FindByIdAsync(refreshToken.UserId.ToString());
            IList<Claim> userClaims = await _userService.GetClaimsAsync(user);

            if (user is not null)
            {
                string accessToken = _jwtService.GenerateAccessToken(user, userClaims, _loginProvider);
                await _jwtService.UpdateLastUsedAtAsync(refreshToken);
                return Ok(new { accessToken });
            }
            return BadRequest("Refresh token invalid");
        }

        /// <summary>
        /// Signs out a user from the current device (deletes refresh token).
        /// </summary>
        /// <remarks>
        /// Method succeeds only if a correct refresh_token Cookie is supplied.
        /// </remarks>
        /// <response code="200">Returns a success message.</response>
        /// <response code="400">Returns an error message.</response>
        /// <response code="403">Returns an error message when trying to use someone else's token.</response>
        [Authorize]
        [HttpPost("[Action]")]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(string), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(string), StatusCodes.Status403Forbidden)]
        public new async Task<ActionResult> SignOut()
        {
            string token = Request.Cookies.RefreshToken();

            if (token is null)
            {
                return BadRequest($"No {RefreshTokenConfiguration.CookieName} cookie found.");
            }

            RefreshToken refreshToken = await _jwtService.ParseRefreshTokenAsync(token);

            if (refreshToken is null)
            {
                return BadRequest("Invalid refresh token.");
            }

            if (User.Id() != refreshToken.UserId)
            {
                return Forbid("Cannot revoke someone else's token.");
            }

            string revokingRefreshToken = HttpContext.Request.Cookies.RefreshToken();
            string revokingIpAddress = HttpContext.Request.IpAddress();

            bool signOutSuccessful = await _jwtService.RevokeRefreshTokenAsync(refreshToken, revokingRefreshToken, revokingIpAddress);

            // Need to add more specific messaging here
            // Modify token provider
            if (signOutSuccessful)
            {
                Response.Cookies.DeleteRefreshToken();
                return Ok($"Successfully signed out from { refreshToken.Name }.");
            }

            return BadRequest("Could not sign out.");
        }
    }
}
