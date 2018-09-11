using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BlueOxCore.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace BlueOxCore.Controllers
{
    [Produces("application/json")]
    [Route("BlueOx")]
    public class BlueOxController : Controller
    {
        // GET: api/BlueOxSecurity/Is2FAEnable
        [HttpPost]
        [Route("2fa/Register")]
        public IActionResult Register([FromBody]RequestClass param)
        {
            TwoFactAuthentication objTwoFactAuthentication = new TwoFactAuthentication();
            return Ok(objTwoFactAuthentication.Is2FAEnable(param.UserName));
        }

        // GET: api/BlueOxSecurity/VerifyCode
        [HttpPost]
        [Route("2fa/Verify")]
        public IActionResult Verify([FromBody]RequestClass param)
        {
            TwoFactAuthentication objTwoFactAuthentication = new TwoFactAuthentication();
            return Ok(objTwoFactAuthentication.VerifyCode(param.UserName, param.AppCode));
        }

        // GET: api/BlueOxSecurity/Renew
        [HttpPost]
        [Route("2fa/Renew")]
        public IActionResult Renew([FromBody]RequestClass param)
        {
            TwoFactAuthentication objTwoFactAuthentication = new TwoFactAuthentication();
            return Ok(objTwoFactAuthentication.Renew(param.UserName));
        }
    }
}