using AdminLogin.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace SimpleAdminLogin.Controllers
{
    public class AccountController : Controller
    {
        private readonly AdminCredentials _adminCredentials;

        // Inject the IOptions to get the configured credentials
        public AccountController(IOptions<AdminCredentials> adminCredentialsOptions)
        {
            _adminCredentials = adminCredentialsOptions.Value;
        }

        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                // Check if the provided username and password match the ones in appsettings.json
                if (model.Username == _adminCredentials.Username && model.Password == _adminCredentials.Password)
                {
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, model.Username),
                        new Claim(ClaimTypes.Role, "Admin"),
                    };

                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var authProperties = new AuthenticationProperties
                    {
                        // You can set additional properties here
                        IsPersistent = true // To make the cookie persistent across browser sessions
                    };

                    // Sign in the user, which creates the authentication cookie
                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(claimsIdentity),
                        authProperties);

                    // Redirect to the original URL or to the admin dashboard
                    return RedirectToLocal(returnUrl);
                }

                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(model);
            }
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            // Sign out the user, which clears the authentication cookie
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        public IActionResult AccessDenied()
        {
            return View();
        }

        private IActionResult RedirectToLocal(string? returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                // Default redirect to the admin area after successful login
                return RedirectToAction("Index", "Admin");
            }
        }
    }
}