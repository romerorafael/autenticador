using AngularAuthAPI.Context;
using AngularAuthAPI.Helper;
using AngularAuthAPI.Model;
using AngularAuthAPI.Model.Dto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;

        public UserController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null) { return BadRequest(); }

            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName);

            if (user == null) { return NotFound(new { Message = "Usuário/Senha não correspondente" }); }
            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password)) { return NotFound(new { Message = "Usuário/Senha não correspondente" }); }
            

            user.Token = CreateJWT(user);

            var newAccessToken = user.Token;
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _authContext.SaveChangesAsync();

            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null) { return BadRequest(); }
            if(await CheckUserNameExist(userObj.UserName)) {  return BadRequest(new {Message="Usuário já existente"}); }
            if(await CheckEmailExist(userObj.Email)) {  return BadRequest(new {Message="E-mail já existente"}); }
            var pass = CheckPassordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(pass)) { return BadRequest(new { Message = pass }); }

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "Admin";
            userObj.Token = "";
            userObj.Email = userObj.Email.ToLower();

            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();

            return Ok(new
            {
                Message = "Usuário registrado com sucesso"
            });

        }

        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUser()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }

        [HttpGet("refresh")]
        public async Task<IActionResult> Refresh (TokenApiDto tokenApiDto)
        {
            if(tokenApiDto is null) { return BadRequest("Requisição inválida"); }

            string accessToken = tokenApiDto.AccessToken;
            string refresh = tokenApiDto.RefreshToken;

            var princial = GetPrincipleFromExpiredToken(accessToken);

            var username = princial.Identity.Name;
            var user = await _authContext.Users.FirstOrDefaultAsync(u => u.UserName == username);
            if (user is null || user.RefreshToken != refresh || user.RefreshTokenExpireTime <= DateTime.Now) { return BadRequest("Requisição inválida"); }

            var newAccessToken = CreateJWT(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpireTime = DateTime.Now.AddDays(5);
            await _authContext.SaveChangesAsync();

            return Ok(new
            {
                AccesToken = newAccessToken,
                RefreshToken = newRefreshToken,
            });
        }

        private Task<bool> CheckUserNameExist(string username)
        {
            return _authContext.Users.AnyAsync(x => x.UserName == username);
        }

        private Task<bool> CheckEmailExist(string email)
        {
            return _authContext.Users.AnyAsync(x => x.Email == email);
        }

        private string CheckPassordStrength(string pass)
        {
            StringBuilder sb = new StringBuilder();

            if(pass.Length < 8) { sb.Append("Senha deve ter no mínimo 8 caracters" + Environment.NewLine); }
            if(!(Regex.IsMatch(pass, "[a-z]") && Regex.IsMatch(pass,"[A-Z]") && Regex.IsMatch(pass,"[0-9]")))
            {
                sb.Append("A senha deve conter alfanumérico" + Environment.NewLine);
            }
            if (!Regex.IsMatch(pass, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]")) {
                sb.Append("A senha deve conter caracteres especiais" + Environment.NewLine);
            }

            return sb.ToString();
        }

        private string CreateJWT(User user) {

            
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysecret....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}")
            });

            var credential = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(10),
                SigningCredentials = credential,
                NotBefore = DateTime.Now,
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);

            return jwtTokenHandler.WriteToken(token);

        }

        private ClaimsPrincipal GetPrincipleFromExpiredToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("veryverysecret....");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecuryToken = securityToken as JwtSecurityToken;
            if (jwtSecuryToken == null || !jwtSecuryToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Token inválido");

            return principal;
        }

        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refresToken = Convert.ToBase64String(tokenBytes);

            var tokenInUser = _authContext.Users.Any(a=> a.RefreshToken == refresToken);
            if(tokenInUser)
            {
                return CreateRefreshToken();
            }

            return refresToken;
        }
    }
}
