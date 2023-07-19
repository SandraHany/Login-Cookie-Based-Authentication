using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;




namespace AuthenticationCookies.Pages;

public class IndexModel : PageModel
{

    [BindProperty]
    public LoginInput LoginInput { get; set; }
    public bool IsLoggedIn = false;
    public Task<LoginInput> AuthenticateUser(string name, string password)
    {
        LoginInput user = null;
        if (name == "intern" && password == "summer 2023 july")
        {
            user = LoginInput;
        }
        return Task.FromResult(user);
    }
    public async Task<IActionResult> OnPostAsync()
    {

        if (ModelState.IsValid)
        {

            var user = await AuthenticateUser(LoginInput.Username, LoginInput.Password);

            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return Page();
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),

            };

            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity));


            return RedirectToPage(); ;
        }

        return Page();
    }
    public void OnGet()
    {
        if (User.Identity.IsAuthenticated)
        {
            IsLoggedIn = true;
        }
    }
    public async Task<IActionResult> OnPostLogout()
    {
        await HttpContext.SignOutAsync(
            CookieAuthenticationDefaults.AuthenticationScheme
        );

        return RedirectToPage();
    }
}
public class LoginInput
{
    [Required(ErrorMessage = "Username is required.")]
    public string Username { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    public string Password { get; set; }
}