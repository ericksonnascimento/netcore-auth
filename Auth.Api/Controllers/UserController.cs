using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using Auth.Api.Configuration;
using Auth.Api.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Api.Controllers
{
    [Route("api/[controller]")]
    public class UserController: Controller
    {
        [AllowAnonymous]
        [HttpPost("login")]
        public object Login([FromBody]Login login,
                            [FromServices]SigningConfigurations signingConfigurations,
                            [FromServices]TokenConfiguration tokenConfigurations)
        {
            var credenciasValidas = true; //Implementar a lógica e setar de acordos

            string idUsuario = Guid.NewGuid().ToString(); //Recupera de acordo 
            
            if(credenciasValidas)
            {

                var identity = new ClaimsIdentity(
                   new GenericIdentity(idUsuario, "Login"),
                   new[] {
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                        new Claim(JwtRegisteredClaimNames.UniqueName, login.Username)
                   }
               );

                var dataCriacao = DateTime.Now;
                var dataExpiracao = dataCriacao +
                    TimeSpan.FromSeconds(tokenConfigurations.Seconds);
                var handler = new JwtSecurityTokenHandler();
                var securityToken = handler.CreateToken(new SecurityTokenDescriptor
                {
                    Issuer = tokenConfigurations.Issuer,
                    Audience = tokenConfigurations.Audience,
                    SigningCredentials = signingConfigurations.SigningCredentials,
                    Subject = identity,
                    NotBefore = dataCriacao,
                    Expires = dataExpiracao
                });
                var token = handler.WriteToken(securityToken);
                return new
                {
                    authenticated = true,
                    created = dataCriacao.ToString("yyyy-MM-dd HH:mm:ss"),
                    expiration = dataExpiracao.ToString("yyyy-MM-dd HH:mm:ss"),
                    accessToken = token,
                    message = "Autenticado com sucesso."
                };
            }
            else
            {
                return new
                {
                    authenticated = false,
                    message = "E-mail/senha inválidos."
                };
            }
        }

        [Authorize("Bearer")]
        [HttpGet("info")]
        public ActionResult GetInfo()
        {
            var idUsuario = User.Identity.Name;
            return Ok(idUsuario);
        }
    }
}